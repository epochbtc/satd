//! Phase C — live block-acceptance differential against a real Bitcoin Core.
//!
//! Phase B (`node/tests/feature_block_consensus.rs`) pins satd's block- and
//! tx-level verdicts against Core reasons *hand-transcribed* from
//! `feature_block.py`. Phase C runs the same family of adversarial blocks /
//! transactions against a **live** `bitcoind` (spawned in Docker, see
//! `common::core_node`) and asserts satd reaches the *identical* verdict —
//! Core is the oracle, observed at runtime rather than baked in.
//!
//! What this adds over Phase B:
//!   1. It exercises satd's REAL composite acceptance path (`accept_block`,
//!      reached through the `submitblock` RPC), not the unit functions
//!      `check_block` / `connect_block` called in isolation.
//!   2. It re-validates the hand-transcribed Phase-B reject strings against a
//!      real Core, and reports (without failing) when the live reason differs
//!      from the baked constant — e.g. wording drift across a Core version.
//!
//! ## How a verdict is obtained
//!
//! Both nodes expose `submitblock` (null = accept, reject-reason string =
//! reject — identical contract) and `testmempoolaccept` (for standalone
//! context-free transaction checks). The harness submits identical bytes to
//! each and compares.
//!
//! ## The shared-tip invariant
//!
//! satd emits `bad-prevblk` (Core: `prev-blk-not-found`) for a block that
//! doesn't connect, and `duplicate` for a known block. If a test block didn't
//! build on a tip BOTH nodes share, those connectivity verdicts would diverge
//! meaninglessly. So the harness mines a shared base by dual-submitting
//! identical valid blocks to both nodes (coinbases pay bare `OP_TRUE`, the
//! `feature_block.py` trick, so spends need no signing and no witness
//! commitment), keeps both tips in lockstep, and builds every candidate on the
//! shared tip. Any connectivity/duplicate verdict from either node is treated
//! as a HARNESS BUG and fails loudly.
//!
//! ## Classification
//!
//!   * both accept                          → match
//!   * both reject, same reason             → match (+ cross-check vs Phase B)
//!   * both reject, documented label diff   → match (pinned `ReasonDiffers`)
//!   * both reject, undeclared diff reason  → REASON DIVERGENCE (fail)
//!   * one accepts, the other rejects       → CONSENSUS DIVERGENCE (fail)
//!   * either returns a connectivity verdict → HARNESS BUG (fail)
//!
//! A handful of Phase-B cases are intentionally NOT reachable through the live
//! RPC oracle (Core's `submitblock` coinbase pre-check, the zero-input SegWit-
//! marker collision) and stay Phase-B-only; see the NOTEs by the case bodies.
//!
//! ## Gating
//!
//! Requires Docker (to spawn Core). Behind the `phase-c` feature so
//! `cargo test --all` skips it; the dedicated canary job enables it. Run
//! locally with:
//!   `cargo test --test phase_c_differential --features phase-c -- --nocapture`

#![cfg(feature = "phase-c")]

mod common;

use bitcoin::block::{Header, Version};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    absolute::LockTime, Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};

use common::core_node::{pull_core_image, CoreNode, Outcome};
use common::TestNode;
use node::chain::connect::block_subsidy;

// ── consensus constants for regtest ───────────────────────────────────
const POWLIMIT_BITS: u32 = 0x207f_ffff;
/// A header version with the BIP9 top bits set — what miners (and satd's own
/// template) use; numerically ≥ 4, so it clears the mandatory block-version
/// gate at every height.
const BLOCK_VERSION: i32 = 0x2000_0000;
/// Regtest genesis timestamp; base-chain block times count up from here so
/// they sit far in the past (always below `now + 2h`, always above MTP).
const GENESIS_TIME: u32 = 1_296_688_602;
const BLOCK_SPACING: u32 = 600;

/// Number of coinbase-only base blocks. Must be ≥ ~101 so the early coinbases
/// are mature (spendable) by the time candidate blocks are built.
const BASE_COINBASES: u32 = 105;

// ── builders ──────────────────────────────────────────────────────────

/// Anyone-can-spend `OP_TRUE` scriptPubKey (bare push of 1). Spent with an
/// empty scriptSig and no witness — no key, no commitment.
fn op_true() -> ScriptBuf {
    ScriptBuf::from(vec![0x51])
}

/// A BIP34 coinbase paying `value` sats to `spk`. `push_int(height)` matches
/// Core's `CScript() << height`, so the BIP34 height check passes on both.
fn coinbase(height: u32, value: u64, spk: ScriptBuf) -> Transaction {
    let script_sig = bitcoin::script::Builder::new()
        .push_int(height as i64)
        .push_opcode(bitcoin::opcodes::all::OP_PUSHBYTES_0) // pad to ≥ 2 bytes
        .into_script();
    Transaction {
        version: TxVersion(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: spk }],
    }
}

/// A non-coinbase transaction spending one outpoint.
fn spend(
    prevout: OutPoint,
    value: u64,
    version: i32,
    sequence: u32,
    locktime: u32,
    spk: ScriptBuf,
) -> Transaction {
    Transaction {
        version: TxVersion(version),
        lock_time: LockTime::from_consensus(locktime),
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: spk }],
    }
}

/// Grind the regtest PoW (trivial). Mirrors `node/src/mining/miner.rs`.
fn grind(header: &mut Header) {
    loop {
        if header.validate_pow(header.target()).is_ok() {
            return;
        }
        header.nonce = header.nonce.wrapping_add(1);
        if header.nonce == 0 {
            header.time += 1;
        }
    }
}

/// Assemble a block on `prev` at `time`. `merkle_override` forces a (bad)
/// merkle root; `bits` and `do_grind` let the PoW cases produce a header with
/// invalid work. By default the merkle root is computed and the PoW ground.
fn assemble(
    prev: BlockHash,
    time: u32,
    bits: u32,
    txdata: Vec<Transaction>,
    merkle_override: Option<TxMerkleNode>,
    do_grind: bool,
) -> Block {
    let mut b = Block {
        header: Header {
            version: Version::from_consensus(BLOCK_VERSION),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        },
        txdata,
    };
    b.header.merkle_root =
        merkle_override.unwrap_or_else(|| b.compute_merkle_root().unwrap_or(TxMerkleNode::all_zeros()));
    if do_grind {
        grind(&mut b.header);
    }
    b
}

/// A plain, fully valid block on `prev` at `height`/`time` carrying `txdata`
/// after its coinbase (coinbase pays the full subsidy to `OP_TRUE`).
fn valid_block(prev: BlockHash, height: u32, time: u32, mut txdata: Vec<Transaction>) -> Block {
    let mut txs = vec![coinbase(height, block_subsidy(height), op_true())];
    txs.append(&mut txdata);
    assemble(prev, time, POWLIMIT_BITS, txs, None, true)
}

fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

// ── satd-side verdict adapters (over JSON-RPC) ─────────────────────────

fn satd_submit_block(node: &TestNode, hex: &str) -> Outcome {
    let resp = node
        .rpc_call_with_params("submitblock", vec![serde_json::json!(hex)])
        .expect("satd submitblock RPC");
    match &resp["result"] {
        serde_json::Value::Null => Outcome::Accept,
        serde_json::Value::String(s) => Outcome::Reject(s.clone()),
        other => Outcome::Reject(format!("unexpected-submitblock-result: {other}")),
    }
}

fn satd_test_mempool_accept(node: &TestNode, hex: &str) -> Outcome {
    let resp = node
        .rpc_call_with_params("testmempoolaccept", vec![serde_json::json!([hex])])
        .expect("satd testmempoolaccept RPC");
    let first = resp["result"].as_array().and_then(|a| a.first()).cloned();
    match first {
        Some(r) if r["allowed"].as_bool().unwrap_or(false) => Outcome::Accept,
        Some(r) => Outcome::Reject(
            r["reject-reason"].as_str().unwrap_or("missing-reject-reason").to_string(),
        ),
        None => Outcome::Reject("missing-testmempoolaccept-result".to_string()),
    }
}

// ── harness state ──────────────────────────────────────────────────────

#[derive(Clone)]
struct CoinRef {
    outpoint: OutPoint,
    amount: u64,
    height: u32,
}

struct Ctx {
    tip_hash: BlockHash,
    tip_height: u32,
    tip_time: u32,
    /// Base coinbase coins, index 0 = height 1. Some may be consumed by the
    /// funding block / accept cases.
    coinbases: Vec<CoinRef>,
    /// Non-coinbase coins created by the funding block (for the BIP68 case,
    /// which needs a low-confirmation non-coinbase input).
    nc_coins: Vec<CoinRef>,
}

impl Ctx {
    fn candidate_height(&self) -> u32 {
        self.tip_height + 1
    }
    fn candidate_time(&self) -> u32 {
        self.tip_time + BLOCK_SPACING
    }
    /// Advance the tracked tip onto an accepted block.
    fn advance_to(&mut self, b: &Block) {
        self.tip_hash = b.block_hash();
        self.tip_height += 1;
        self.tip_time = b.header.time;
    }
    /// First unused mature coinbase (height + 100 ≤ candidate height).
    fn take_mature_coinbase(&self, used: &mut Vec<usize>) -> CoinRef {
        let cand = self.candidate_height();
        for (i, c) in self.coinbases.iter().enumerate() {
            if !used.contains(&i) && c.height + 100 <= cand {
                used.push(i);
                return c.clone();
            }
        }
        panic!("no unused mature coinbase available at height {cand}");
    }
    /// An immature coinbase (height + 100 > candidate height).
    fn immature_coinbase(&self) -> CoinRef {
        let cand = self.candidate_height();
        self.coinbases
            .iter()
            .rev()
            .find(|c| c.height + 100 > cand)
            .cloned()
            .expect("an immature coinbase")
    }
}

// ── base-chain construction (the shared tip) ───────────────────────────

/// Mine `BASE_COINBASES` coinbase-only blocks plus one funding block, dual-
/// submitting each to both nodes and asserting lockstep acceptance. Returns
/// the populated [`Ctx`]. Panics on any divergence — a base block that one
/// node rejects means the two implementations already disagree on a *valid*
/// chain, which invalidates every downstream comparison.
fn build_shared_base(satd: &TestNode, core: &CoreNode) -> Ctx {
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
    // Both must start at the identical regtest genesis.
    assert_eq!(satd_best_hash(satd), genesis.to_string(), "satd not at regtest genesis");
    assert_eq!(core.best_block_hash(), genesis.to_string(), "Core not at regtest genesis");

    let mut ctx = Ctx {
        tip_hash: genesis,
        tip_height: 0,
        tip_time: GENESIS_TIME,
        coinbases: Vec::new(),
        nc_coins: Vec::new(),
    };

    // Coinbase-only base blocks.
    for h in 1..=BASE_COINBASES {
        let time = GENESIS_TIME + h * BLOCK_SPACING;
        let block = valid_block(ctx.tip_hash, h, time, vec![]);
        submit_base_block(satd, core, &block, h);
        let cb_txid = block.txdata[0].compute_txid();
        ctx.coinbases.push(CoinRef {
            outpoint: OutPoint { txid: cb_txid, vout: 0 },
            amount: block_subsidy(h),
            height: h,
        });
        ctx.advance_to(&block);
    }

    // Funding block: spend the first (now-mature) coinbase into 4 OP_TRUE
    // non-coinbase outputs, so the BIP68 case has a low-confirmation
    // non-coinbase input to spend.
    let fund_h = ctx.candidate_height();
    let fund_time = ctx.candidate_time();
    let src = ctx.coinbases[0].clone();
    let per = src.amount / 4;
    let funding_tx = Transaction {
        version: TxVersion(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: src.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: (0..4)
            .map(|_| TxOut { value: Amount::from_sat(per), script_pubkey: op_true() })
            .collect(),
    };
    let funding_txid = funding_tx.compute_txid();
    let fund_block = valid_block(ctx.tip_hash, fund_h, fund_time, vec![funding_tx]);
    submit_base_block(satd, core, &fund_block, fund_h);
    for vout in 0..4u32 {
        ctx.nc_coins.push(CoinRef {
            outpoint: OutPoint { txid: funding_txid, vout },
            amount: per,
            height: fund_h,
        });
    }
    ctx.advance_to(&fund_block);

    // Sanity: both nodes agree on the shared tip and height.
    assert_eq!(satd_best_hash(satd), ctx.tip_hash.to_string(), "satd tip != tracked base tip");
    assert_eq!(core.best_block_hash(), ctx.tip_hash.to_string(), "Core tip != tracked base tip");
    assert_eq!(core.block_count(), ctx.tip_height as u64, "Core height != tracked base height");

    ctx
}

fn submit_base_block(satd: &TestNode, core: &CoreNode, block: &Block, height: u32) {
    let hex = hex::encode(serialize(block));
    let s = satd_submit_block(satd, &hex);
    let c = core.submit_block(&hex);
    assert_eq!(
        s,
        Outcome::Accept,
        "satd rejected base block at height {height}: {s:?}"
    );
    assert_eq!(
        c,
        Outcome::Accept,
        "Core rejected base block at height {height}: {c:?}"
    );
}

fn satd_best_hash(node: &TestNode) -> String {
    node.rpc_call("getbestblockhash")
        .ok()
        .and_then(|r| r["result"].as_str().map(str::to_string))
        .expect("satd getbestblockhash")
}

// ── case model ─────────────────────────────────────────────────────────

enum Submission {
    Block(Block),
    Tx(Transaction),
}

struct Case {
    name: &'static str,
    category: &'static str,
    /// The Core reject reason Phase B baked from `feature_block.py` (None =
    /// accept). Used only to cross-check live Core against the static matrix;
    /// a mismatch is reported, not failed.
    phase_b: Option<&'static str>,
    /// A *documented* reject-label difference: both nodes reject (consensus
    /// agrees the input is invalid) but Core emits a different — usually less
    /// specific — reason string than satd. Set to the exact string Core emits.
    /// This is the `Expect::ReasonDiffers` disposition from Phase B: it proves
    /// satd rejects what Core rejects, while pinning the known label gap so a
    /// *new* divergence still fails. `None` demands exact reason parity.
    core_reason_differs: Option<&'static str>,
    build: fn(&Ctx, &mut Vec<usize>) -> Submission,
}

/// Connectivity / duplicate verdicts that must never appear — their presence
/// means a candidate failed to build on the shared tip (a harness bug), not a
/// consensus signal.
const CONNECTIVITY: &[&str] = &[
    "bad-prevblk",
    "prev-blk-not-found",
    "inconclusive",
    "duplicate",
    "duplicate-invalid",
    "duplicate-inconclusive",
];

fn is_connectivity(o: &Outcome) -> bool {
    matches!(o, Outcome::Reject(r) if CONNECTIVITY.contains(&r.as_str()))
}

// ── cases ──────────────────────────────────────────────────────────────
//
// Each builds its candidate on the shared tip (`ctx`). Reject cases leave the
// tip unchanged; accept cases advance it (handled by the runner).

// -- context-free block structure (submitblock) --
//
// NOTE: `empty_block` (bad-blk-length) and `first_tx_not_coinbase`
// (bad-cb-missing) are NOT in the live set: Core's `submitblock` RPC handler
// pre-checks "block starts with a coinbase" and returns an RPC error
// (`-22 "Block does not start with a coinbase"`) BEFORE consensus validation,
// so these context-free verdicts can't be observed through the submitblock
// oracle. Phase B covers them against `check_block` directly. (satd's
// submitblock runs full validation and returns the consensus reason — a minor
// RPC-wrapper difference, tracked in the monorepo findings, not a consensus
// divergence.)

fn c_multiple_coinbase(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    let txs = vec![
        coinbase(h, block_subsidy(h), op_true()),
        coinbase(h, block_subsidy(h) / 2, op_true()),
    ];
    Submission::Block(assemble(ctx.tip_hash, ctx.candidate_time(), POWLIMIT_BITS, txs, None, true))
}

fn c_bad_merkle_root(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    let txs = vec![coinbase(h, block_subsidy(h), op_true())];
    // Valid PoW over a deliberately wrong merkle root → bad-txnmrklroot
    // (the wrong root is set BEFORE grinding so PoW is valid; otherwise Core
    // would reject `high-hash` first).
    Submission::Block(assemble(
        ctx.tip_hash,
        ctx.candidate_time(),
        POWLIMIT_BITS,
        txs,
        Some(TxMerkleNode::from_byte_array([0xde; 32])),
        true,
    ))
}

fn c_oversize_block(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    let outputs: Vec<TxOut> = (0..40)
        .map(|_| TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from(vec![0x00; 30_000]),
        })
        .collect();
    let cb = {
        let mut c = coinbase(h, block_subsidy(h), op_true());
        c.output = outputs;
        c
    };
    Submission::Block(assemble(ctx.tip_hash, ctx.candidate_time(), POWLIMIT_BITS, vec![cb], None, true))
}

fn c_coinbase_scriptsig_too_short(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    let mut cb = coinbase(h, block_subsidy(h), op_true());
    cb.input[0].script_sig = ScriptBuf::from(vec![0xff]); // 1 byte < 2
    Submission::Block(assemble(ctx.tip_hash, ctx.candidate_time(), POWLIMIT_BITS, vec![cb], None, true))
}

fn c_coinbase_scriptsig_too_long(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    let mut cb = coinbase(h, block_subsidy(h), op_true());
    cb.input[0].script_sig = ScriptBuf::from(vec![0xff; 101]); // > 100
    Submission::Block(assemble(ctx.tip_hash, ctx.candidate_time(), POWLIMIT_BITS, vec![cb], None, true))
}

fn c_merkle_mutation(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    // CVE-2012-2459: an even tx list ending in a duplicated subtree has the
    // same merkle root as the honest odd list → Core flags `mutated` and
    // rejects bad-txns-duplicate.
    let h = ctx.candidate_height();
    let t1 = spend(OutPoint { txid: bitcoin::Txid::from_byte_array([0x11; 32]), vout: 0 }, 1_000, 1, 0xffff_ffff, 0, op_true());
    let t2 = spend(OutPoint { txid: bitcoin::Txid::from_byte_array([0x22; 32]), vout: 0 }, 1_000, 1, 0xffff_ffff, 0, op_true());
    let txs = vec![coinbase(h, block_subsidy(h), op_true()), t1, t2.clone(), t2];
    Submission::Block(assemble(ctx.tip_hash, ctx.candidate_time(), POWLIMIT_BITS, txs, None, true))
}

// -- context-free transaction (testmempoolaccept) --
//
// NOTE: `tx_no_inputs` (bad-txns-vin-empty) is NOT in the live set: a
// zero-input transaction's serialization collides with the SegWit marker byte
// (`...00...`), so Core's deserializer rejects the bytes as malformed
// (`-22 "TX decode failed … at least one input"`) rather than reaching
// `CheckTransaction`. It is unrepresentable on the wire as a non-witness tx.
// Phase B covers it against `check_transaction` directly.

fn c_tx_no_outputs(_ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    Submission::Tx(Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([0xab; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![],
    })
}

fn c_tx_output_over_max(_ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    Submission::Tx(spend(
        OutPoint { txid: bitcoin::Txid::from_byte_array([0xab; 32]), vout: 0 },
        21_000_001 * 100_000_000,
        1,
        0xffff_ffff,
        0,
        op_true(),
    ))
}

fn c_tx_duplicate_inputs(_ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let op = OutPoint { txid: bitcoin::Txid::from_byte_array([0xab; 32]), vout: 0 };
    let dup = TxIn {
        previous_output: op,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    Submission::Tx(Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![dup.clone(), dup],
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: op_true() }],
    })
}

fn c_non_coinbase_null_input(_ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    Submission::Tx(Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([0xab; 32]), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: op_true() }],
    })
}

fn c_tx_oversize(_ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let big = ScriptBuf::from(vec![0x00; 1_100_000]); // ~1.1 MB → *4 > MAX_BLOCK_WEIGHT
    Submission::Tx(Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([0xab; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: big }],
    })
}

// -- proof-of-work / timestamp (submitblock) --

fn c_high_hash(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    let txs = vec![coinbase(h, block_subsidy(h), op_true())];
    // Hard (mainnet-ish) bits, NOT ground → hash fails the claimed target.
    Submission::Block(assemble(ctx.tip_hash, ctx.candidate_time(), 0x1d00_ffff, txs, None, false))
}

fn c_time_too_new(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    let txs = vec![coinbase(h, block_subsidy(h), op_true())];
    // 3 hours ahead of real now → beyond the 2h future-time slack.
    Submission::Block(assemble(ctx.tip_hash, now_secs() + 3 * 3600, POWLIMIT_BITS, txs, None, true))
}

fn c_time_too_old(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    let txs = vec![coinbase(h, block_subsidy(h), op_true())];
    // At/below the median-time-past of the last 11 blocks → time-too-old.
    Submission::Block(assemble(ctx.tip_hash, GENESIS_TIME, POWLIMIT_BITS, txs, None, true))
}

// -- contextual / chain-level (submitblock) --

fn c_spend_nonexistent(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let fake = OutPoint { txid: bitcoin::Txid::from_byte_array([0xab; 32]), vout: 0 };
    let s = spend(fake, 1_000, 2, 0xffff_ffff, 0, op_true());
    Submission::Block(valid_block(ctx.tip_hash, ctx.candidate_height(), ctx.candidate_time(), vec![s]))
}

fn c_coinbase_value_too_high(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    let cb = coinbase(h, block_subsidy(h) + 1, op_true()); // no fees → over subsidy
    Submission::Block(assemble(ctx.tip_hash, ctx.candidate_time(), POWLIMIT_BITS, vec![cb], None, true))
}

fn c_bad_coinbase_height(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    // BIP34 height encodes 999, but the block is at `h`.
    let cb = coinbase(999, block_subsidy(h), op_true());
    Submission::Block(assemble(ctx.tip_hash, ctx.candidate_time(), POWLIMIT_BITS, vec![cb], None, true))
}

fn c_block_sigops(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let h = ctx.candidate_height();
    // 4001 bare OP_CHECKMULTISIG → 4001·20·4 sigop cost > 80_000.
    let script = ScriptBuf::from(vec![bitcoin::opcodes::all::OP_CHECKMULTISIG.to_u8(); 4001]);
    let mut cb = coinbase(h, block_subsidy(h), op_true());
    cb.output = vec![TxOut { value: Amount::from_sat(0), script_pubkey: script }];
    Submission::Block(assemble(ctx.tip_hash, ctx.candidate_time(), POWLIMIT_BITS, vec![cb], None, true))
}

fn c_inputs_below_outputs(ctx: &Ctx, used: &mut Vec<usize>) -> Submission {
    let coin = ctx.take_mature_coinbase(used);
    // Pay out more than the input provides → bad-txns-in-belowout.
    let s = spend(coin.outpoint, coin.amount + 100_000_000, 2, 0xffff_ffff, 0, op_true());
    Submission::Block(valid_block(ctx.tip_hash, ctx.candidate_height(), ctx.candidate_time(), vec![s]))
}

fn c_immature_coinbase_spend(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    let coin = ctx.immature_coinbase();
    let s = spend(coin.outpoint, coin.amount, 2, 0xffff_ffff, 0, op_true());
    Submission::Block(valid_block(ctx.tip_hash, ctx.candidate_height(), ctx.candidate_time(), vec![s]))
}

fn c_locktime_not_final(ctx: &Ctx, used: &mut Vec<usize>) -> Submission {
    let coin = ctx.take_mature_coinbase(used);
    // Height-based locktime far in the future + non-max sequence → non-final.
    let s = spend(coin.outpoint, coin.amount, 2, 0, 1_000_000, op_true());
    Submission::Block(valid_block(ctx.tip_hash, ctx.candidate_height(), ctx.candidate_time(), vec![s]))
}

fn c_bip68_sequence_not_met(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    // Spend a low-confirmation NON-coinbase coin (from the funding block) with
    // a v2 relative-locktime requiring more blocks than have elapsed.
    let coin = ctx.nc_coins[0].clone();
    let s = spend(coin.outpoint, coin.amount, 2, 16, 0, op_true()); // require 16 blocks
    Submission::Block(valid_block(ctx.tip_hash, ctx.candidate_height(), ctx.candidate_time(), vec![s]))
}

// -- accept cases (advance the tip) --

fn c_valid_block(ctx: &Ctx, _u: &mut Vec<usize>) -> Submission {
    Submission::Block(valid_block(ctx.tip_hash, ctx.candidate_height(), ctx.candidate_time(), vec![]))
}

fn c_mature_coinbase_spend_ok(ctx: &Ctx, used: &mut Vec<usize>) -> Submission {
    let coin = ctx.take_mature_coinbase(used);
    let s = spend(coin.outpoint, coin.amount, 2, 0xffff_ffff, 0, op_true()); // no fee
    Submission::Block(valid_block(ctx.tip_hash, ctx.candidate_height(), ctx.candidate_time(), vec![s]))
}

fn c_intra_block_spend_ok(ctx: &Ctx, used: &mut Vec<usize>) -> Submission {
    let coin = ctx.take_mature_coinbase(used);
    let mid = spend(coin.outpoint, coin.amount, 2, 0xffff_ffff, 0, op_true());
    let mid_txid = mid.compute_txid();
    let child = spend(OutPoint { txid: mid_txid, vout: 0 }, coin.amount, 2, 0xffff_ffff, 0, op_true());
    Submission::Block(valid_block(ctx.tip_hash, ctx.candidate_height(), ctx.candidate_time(), vec![mid, child]))
}

fn cases() -> Vec<Case> {
    // Shorthand: most cases demand exact reason parity (`core_reason_differs:
    // None`). Only the documented BIP68 label gap sets it.
    fn case(
        name: &'static str,
        category: &'static str,
        phase_b: Option<&'static str>,
        build: fn(&Ctx, &mut Vec<usize>) -> Submission,
    ) -> Case {
        Case { name, category, phase_b, core_reason_differs: None, build }
    }
    vec![
        // context-free block structure
        case("multiple_coinbase", "block-structure", Some("bad-cb-multiple"), c_multiple_coinbase),
        case("bad_merkle_root", "block-structure", Some("bad-txnmrklroot"), c_bad_merkle_root),
        case("oversize_block", "block-structure", Some("bad-blk-length"), c_oversize_block),
        case("coinbase_scriptsig_too_short", "block-structure", Some("bad-cb-length"), c_coinbase_scriptsig_too_short),
        case("coinbase_scriptsig_too_long", "block-structure", Some("bad-cb-length"), c_coinbase_scriptsig_too_long),
        case("merkle_mutation_cve_2012_2459", "block-structure", Some("bad-txns-duplicate"), c_merkle_mutation),
        // context-free transaction
        case("tx_no_outputs", "tx-context-free", Some("bad-txns-vout-empty"), c_tx_no_outputs),
        case("tx_output_over_max", "tx-context-free", Some("bad-txns-vout-toolarge"), c_tx_output_over_max),
        case("tx_duplicate_inputs", "tx-context-free", Some("bad-txns-inputs-duplicate"), c_tx_duplicate_inputs),
        case("non_coinbase_null_input", "tx-context-free", Some("bad-txns-prevout-null"), c_non_coinbase_null_input),
        case("tx_oversize", "tx-context-free", Some("bad-txns-oversize"), c_tx_oversize),
        // proof-of-work / timestamp
        case("high_hash_bad_pow", "pow-timestamp", Some("high-hash"), c_high_hash),
        case("time_too_new", "pow-timestamp", Some("time-too-new"), c_time_too_new),
        case("time_too_old_mtp", "pow-timestamp", Some("time-too-old"), c_time_too_old),
        // contextual / chain-level (reject)
        case("spend_nonexistent", "contextual", Some("bad-txns-inputs-missingorspent"), c_spend_nonexistent),
        case("coinbase_value_too_high", "contextual", Some("bad-cb-amount"), c_coinbase_value_too_high),
        case("bad_coinbase_height_bip34", "contextual", Some("bad-cb-height"), c_bad_coinbase_height),
        case("block_sigops", "contextual", Some("bad-blk-sigops"), c_block_sigops),
        case("inputs_below_outputs", "contextual", Some("bad-txns-in-belowout"), c_inputs_below_outputs),
        case("immature_coinbase_spend", "contextual", Some("bad-txns-premature-spend-of-coinbase"), c_immature_coinbase_spend),
        case("locktime_not_final", "contextual", Some("bad-txns-nonfinal"), c_locktime_not_final),
        // BIP68 relative-locktime violation: BOTH reject (consensus agrees the
        // tx is invalid), but in block context Core labels it `bad-txns-nonfinal`
        // where satd emits the more specific `bad-txns-nonBIP68-final`. Pinned
        // as a documented label difference.
        Case {
            name: "bip68_sequence_not_met",
            category: "contextual",
            phase_b: Some("bad-txns-nonBIP68-final"),
            core_reason_differs: Some("bad-txns-nonfinal"),
            build: c_bip68_sequence_not_met,
        },
        // accept cases (advance the tip — must run last)
        case("valid_block", "accept", None, c_valid_block),
        case("mature_coinbase_spend_ok", "accept", None, c_mature_coinbase_spend_ok),
        case("intra_block_spend_ok", "accept", None, c_intra_block_spend_ok),
    ]
}

// ── the test ───────────────────────────────────────────────────────────

#[test]
fn phase_c_live_differential() {
    pull_core_image();
    let mut satd = TestNode::start(&[]);
    let core = CoreNode::start();

    let mut ctx = build_shared_base(&satd, &core);

    // Negative control for the orphan guard: a block on a bogus prev must trip
    // the connectivity verdict (`bad-prevblk`). This proves the guard actually
    // fires, so a stray connectivity verdict can never silently masquerade as a
    // matching reject and hide a real divergence later.
    {
        let bogus = BlockHash::from_byte_array([0x99; 32]);
        let blk = valid_block(bogus, ctx.tip_height + 1, ctx.candidate_time(), vec![]);
        let out = satd_submit_block(&satd, &hex::encode(serialize(&blk)));
        assert!(
            is_connectivity(&out),
            "orphan-guard self-check: expected a connectivity verdict for a bogus-prev block, got {out:?}"
        );
    }

    let mut report = String::from(
        "\nPhase C live differential (satd vs Bitcoin Core, submitblock/testmempoolaccept)\n",
    );
    let mut failures: Vec<String> = Vec::new();
    let mut phase_b_notes: Vec<String> = Vec::new();
    // Index 0 (coinbase at height 1) was consumed by the funding block.
    let mut used_coinbases: Vec<usize> = vec![0];

    for case in cases() {
        let submission = (case.build)(&ctx, &mut used_coinbases);
        let (satd_out, core_out) = match &submission {
            Submission::Block(b) => {
                let hex = hex::encode(serialize(b));
                (satd_submit_block(&satd, &hex), core.submit_block(&hex))
            }
            Submission::Tx(t) => {
                let hex = hex::encode(serialize(t));
                (satd_test_mempool_accept(&satd, &hex), core.test_mempool_accept(&hex))
            }
        };

        // Connectivity / duplicate verdicts mean the candidate didn't build on
        // the shared tip — a harness bug, not a consensus signal.
        if is_connectivity(&satd_out) || is_connectivity(&core_out) {
            failures.push(format!(
                "HARNESS BUG {}: connectivity verdict (satd={satd_out:?}, core={core_out:?})",
                case.name
            ));
            continue;
        }

        match (&satd_out, &core_out) {
            (Outcome::Accept, Outcome::Accept) => {
                report.push_str(&format!("✓ [{:<16}] {:<32} accept == Core\n", case.category, case.name));
                if let Submission::Block(b) = &submission {
                    ctx.advance_to(b);
                }
            }
            (Outcome::Reject(a), Outcome::Reject(b)) if a == b => {
                report.push_str(&format!("✓ [{:<16}] {:<32} reject({a}) == Core\n", case.category, case.name));
                // Cross-check the live Core reason against Phase B's baked
                // constant. A mismatch is informational (e.g. wording moved
                // across a Core version), not a failure.
                if case.phase_b.is_some_and(|pb| pb != a) {
                    phase_b_notes.push(format!(
                        "{}: live Core reason `{a}` differs from Phase-B constant `{:?}`",
                        case.name, case.phase_b
                    ));
                }
            }
            (Outcome::Reject(a), Outcome::Reject(b)) if case.core_reason_differs == Some(b.as_str()) => {
                // Documented ReasonDiffers: both reject (no consensus split),
                // Core uses a known different label. Pinned so a *new*
                // divergence still fails.
                report.push_str(&format!(
                    "~ [{:<16}] {:<32} reject(satd:{a} / core:{b}) [documented label diff]\n",
                    case.category, case.name
                ));
            }
            (Outcome::Reject(a), Outcome::Reject(b)) => {
                failures.push(format!(
                    "REASON DIVERGENCE {}: satd rejected `{a}`, Core rejected `{b}`",
                    case.name
                ));
            }
            (Outcome::Accept, Outcome::Reject(b)) => {
                failures.push(format!(
                    "CONSENSUS DIVERGENCE {}: satd ACCEPTED but Core rejected `{b}`",
                    case.name
                ));
            }
            (Outcome::Reject(a), Outcome::Accept) => {
                failures.push(format!(
                    "CONSENSUS DIVERGENCE {}: satd rejected `{a}` but Core ACCEPTED",
                    case.name
                ));
            }
        }
    }

    report.push_str(&format!("\n{} cases, {} failures\n", cases().len(), failures.len()));
    if !phase_b_notes.is_empty() {
        report.push_str("\nPhase-B constant cross-check notes (informational):\n");
        for n in &phase_b_notes {
            report.push_str(&format!("  • {n}\n"));
        }
    }
    println!("{report}");

    satd.stop();
    assert!(failures.is_empty(), "Phase C differential divergences:\n{}", failures.join("\n"));
}
