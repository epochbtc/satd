//! Golden block-level consensus fixtures.
//!
//! Ported from Bitcoin Core's `test/functional/feature_block.py` (the
//! `FullBlockTest`), this is a differential matrix that pins satd's
//! block- and chain-level validation verdicts against Bitcoin Core's
//! reference behavior. Core is the oracle: every case carries the exact
//! reject-reason string Core produces (or `Accept`), and the runner
//! asserts how satd's verdict relates to it.
//!
//! Phase B of the consensus differential-fuzzing roadmap. Unlike a live
//! fuzzer this needs no external `bitcoind`: Core's verdicts are baked in
//! from `feature_block.py`. The suite targets satd's validation entry
//! points directly — `check_block` (context-free block structure),
//! `check_transaction` (context-free tx), `connect_block` (contextual /
//! chain-level), and the `pow` checks — the same layering Core's own
//! fuzz harnesses use.
//!
//! # Gating model (canary, not advisory)
//!
//! Each case declares an [`Expect`] describing satd's *current* relation
//! to Core:
//!   * [`Expect::Match`]        — satd matches Core exactly (verdict + reason).
//!   * [`Expect::ReasonDiffers`] — both reject, but satd uses a different
//!     reason label than Core. Documented; gated to keep producing it.
//!   * [`Expect::Gap`]          — Core rejects, satd does **not** (accepts).
//!     A real, known consensus gap. Documented; gated to stay open.
//!
//! The runner fails CI if reality drifts from the declared expectation in
//! EITHER direction: an `Expect::Match` case that stops matching is a
//! regression; an `Expect::Gap` case that starts matching means the gap
//! was closed and the case must be promoted to `Match` (the test says so
//! explicitly). Nothing is silently ignored.
//!
//! Consensus gaps this suite originally surfaced — all four are now ENFORCED
//! (each case is an `Expect::Match` against Core) as of the block-consensus
//! gap fixes; they remain in the matrix as live regression guards:
//!   * `bad-blk-sigops`   — block-wide sigop-cost limit in `connect_block`.
//!   * `bad-txns-BIP30`   — duplicate-unspent-txid (BIP30) check.
//!   * `time-too-new`     — 2-hour-ahead future-timestamp rejection.
//!   * `bad-version`      — mandatory block-version gate (BIP34/66/65).
//!
//! The deeper code-path equivalence audit (vs Core v28) then surfaced two
//! further divergences, both now ENFORCED (`Expect::Match`) and retained as
//! live regression guards:
//!   * `bad-txns-duplicate` — merkle-tree mutation / CVE-2012-2459, now
//!     detected by `check_block`'s `merkle_tree_mutated` flag (Core parity).
//!   * `bad-txns-oversize`  — per-transaction weight cap now enforced in
//!     `check_transaction` (previously only the block-weight check covered it).
//!
//! Finally, the four cases that previously rejected with a satd-specific reason
//! string (tracked as `Expect::ReasonDiffers`) have been aligned to Core's exact
//! reject reason and promoted to `Expect::Match`: empty block (`bad-blk-length`),
//! missing/!match witness commitment (`bad-witness-merkle-match`), output over
//! `MAX_MONEY` (`bad-txns-vout-toolarge`), and bad PoW (`high-hash`). The matrix
//! is now 32/32 exact (verdict **and** reject reason) against Core.

use bitcoin::absolute::LockTime;
use bitcoin::block::Header;
use bitcoin::hashes::Hash as _;
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, Network, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
    Txid, Witness,
};

use node::chain::connect::{block_subsidy, check_block_version, connect_block, ConnectParams};
use node::storage::blockindex::{BlockIndexEntry, BlockStatus};
use node::storage::coinview::Coin;
use node::storage::db::InMemoryStore;
use node::storage::flatfile::FlatFilePos;
use node::storage::{Store, StoreBatch};
use node::validation::block::check_block;
use node::validation::pow::{
    check_difficulty, check_future_timestamp, check_proof_of_work, check_timestamp,
};
use node::validation::script::NoopVerifier;
use node::validation::tx::check_transaction;

// ── Core reference verdicts ───────────────────────────────────────────

/// The verdict Bitcoin Core produces for a case (the oracle).
#[derive(Clone, Copy, Debug)]
enum Core {
    Accept,
    /// Reject with this exact `BlockValidationState` / `TxValidationState`
    /// reject reason (as emitted by `feature_block.py`'s `reject_reason`).
    Reject(&'static str),
}

/// How satd currently relates to the Core verdict.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// satd matches Core exactly: same accept/reject, and on reject the
    /// same reason string.
    Match,
    /// satd rejects (like Core) but with a *different* reason label.
    /// The string is the reason satd currently emits. No cases currently carry
    /// this disposition (all reject-reason strings now align with Core), but the
    /// variant and its runner arms are retained so a future divergence can be
    /// pinned without re-plumbing.
    #[allow(dead_code)]
    ReasonDiffers(&'static str),
    /// Core rejects but satd accepts — a known, unclosed consensus gap.
    /// The runner keeps it pinned open and fails the day a fix closes it,
    /// forcing promotion to `Match`. No cases currently carry this disposition
    /// (all surfaced gaps are closed), but the variant and its runner arms are
    /// retained so a future audit finding can be pinned without re-plumbing.
    #[allow(dead_code)]
    Gap,
}

/// satd's observed outcome: `Ok(())` = accept, `Err(reason)` = reject with
/// that reason string (the thiserror `Display`, which we deliberately keep
/// equal to Core's reject reasons).
type Satd = Result<(), String>;

struct Case {
    name: &'static str,
    core: Core,
    expect: Expect,
    run: fn() -> Satd,
}

// ── Builders ──────────────────────────────────────────────────────────

const REGTEST_POWLIMIT_BITS: u32 = 0x207f_ffff;
const BASE_TIME: u32 = 1_700_000_000;

fn pos() -> FlatFilePos {
    FlatFilePos { file_number: 0, data_pos: 0 }
}

/// A coinbase paying `value` sats, with a BIP34 height-encoded scriptSig.
fn coinbase(height: u32, value: u64) -> Transaction {
    coinbase_with_outputs(
        height,
        vec![TxOut { value: Amount::from_sat(value), script_pubkey: bitcoin::ScriptBuf::new() }],
    )
}

fn coinbase_with_outputs(height: u32, output: Vec<TxOut>) -> Transaction {
    let script_sig = bitcoin::script::Builder::new()
        .push_int(height as i64)
        .push_opcode(bitcoin::opcodes::OP_FALSE)
        .into_script();
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output,
    }
}

/// Wrap txns into a regtest-shaped block with a correct merkle root.
fn block_of(txdata: Vec<Transaction>) -> Block {
    let mut b = Block {
        header: Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: BASE_TIME,
            bits: CompactTarget::from_consensus(REGTEST_POWLIMIT_BITS),
            nonce: 0,
        },
        txdata,
    };
    b.header.merkle_root = b.compute_merkle_root().unwrap_or(TxMerkleNode::all_zeros());
    b
}

fn block_index_entry(height: u32, time: u32, bits: u32) -> BlockIndexEntry {
    let mut header = bitcoin::constants::genesis_block(Network::Regtest).header;
    header.time = time;
    header.bits = CompactTarget::from_consensus(bits);
    BlockIndexEntry {
        header,
        height,
        status: BlockStatus::Valid,
        num_tx: 1,
        file_number: 0,
        data_pos: 0,
        chainwork: [0u8; 32],
    }
}

/// An InMemoryStore pre-seeded with one spendable coin.
fn store_with_coin(amount: u64, height: u32, coinbase: bool) -> (InMemoryStore, OutPoint) {
    let store = InMemoryStore::new();
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x42; 32]));
    let outpoint = OutPoint { txid, vout: 0 };
    let coin = Coin { amount, script_pubkey: bitcoin::ScriptBuf::new(), height, coinbase };
    let mut batch = StoreBatch::default();
    batch.coin_puts.push((outpoint, coin));
    store.write_batch(batch).unwrap();
    (store, outpoint)
}

fn spending_tx(prevout: OutPoint, value: u64, version: i32, sequence: u32, locktime: u32) -> Transaction {
    Transaction {
        version: Version(version),
        lock_time: LockTime::from_consensus(locktime),
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: bitcoin::ScriptBuf::new() }],
    }
}

// ── satd-verdict adapters ─────────────────────────────────────────────

fn cb(block: &Block) -> Satd {
    check_block(block).map_err(|e| e.to_string())
}

fn tx(tx: &Transaction) -> Satd {
    check_transaction(tx).map_err(|e| e.to_string())
}

fn connect(store: &dyn Store, block: &Block, height: u32, mtp: u32) -> Satd {
    connect_block(&ConnectParams {
        store,
        block,
        height,
        parent_chainwork: &[0u8; 32],
        flat_pos: pos(),
        script_verifier: &NoopVerifier,
        median_time_past: mtp,
        network: Network::Regtest,
        pre_verified_txs: None,
        num_threads: 1,
        precomputed_txids: None,
        address_index: &Default::default(),
        #[cfg(feature = "block-filter-index")]
        filter_index: &Default::default(),
        phase_tracker: None,
    })
    .map(|_| ())
    .map_err(|e| e.to_string())
}

// ── Case bodies ───────────────────────────────────────────────────────
//
// Each returns satd's verdict for one feature_block.py scenario.

// -- context-free block structure (check_block) --

fn case_accept_genesis() -> Satd {
    cb(&bitcoin::constants::genesis_block(Network::Regtest))
}

fn case_empty_block() -> Satd {
    let mut b = bitcoin::constants::genesis_block(Network::Regtest);
    b.txdata.clear();
    cb(&b)
}

fn case_first_tx_not_coinbase() -> Satd {
    let not_cb = spending_tx(
        OutPoint { txid: Txid::from_byte_array([0xab; 32]), vout: 0 },
        50_0000_0000,
        1,
        0xffff_ffff,
        0,
    );
    cb(&block_of(vec![not_cb]))
}

fn case_multiple_coinbase() -> Satd {
    cb(&block_of(vec![coinbase(1, 50_0000_0000), coinbase(1, 25_0000_0000)]))
}

fn case_bad_merkle_root() -> Satd {
    let mut b = bitcoin::constants::genesis_block(Network::Regtest);
    b.header.merkle_root = TxMerkleNode::from_byte_array([0xde; 32]);
    cb(&b)
}

fn case_oversize_block() -> Satd {
    let mut outputs = Vec::new();
    for _ in 0..40 {
        outputs.push(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: bitcoin::ScriptBuf::from(vec![0x00; 30_000]),
        });
    }
    cb(&block_of(vec![coinbase_with_outputs(1, outputs)]))
}

/// A spending tx carrying witness data, but the coinbase has no witness
/// commitment output (BIP141). Core: `bad-witness-merkle-match`.
fn case_witness_commitment_missing() -> Satd {
    let mut witness = Witness::new();
    witness.push([0x01; 72]);
    let mut spend = spending_tx(
        OutPoint { txid: Txid::from_byte_array([0xab; 32]), vout: 0 },
        49_0000_0000,
        1,
        0xffff_ffff,
        0,
    );
    spend.input[0].witness = witness;
    cb(&block_of(vec![coinbase(1, 50_0000_0000), spend]))
}

// -- context-free transaction (check_transaction) --

fn case_tx_no_inputs() -> Satd {
    tx(&Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: bitcoin::ScriptBuf::new() }],
    })
}

fn case_tx_no_outputs() -> Satd {
    tx(&Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0xab; 32]), vout: 0 },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![],
    })
}

fn case_tx_output_over_max() -> Satd {
    tx(&spending_tx(
        OutPoint { txid: Txid::from_byte_array([0xab; 32]), vout: 0 },
        21_000_001 * 100_000_000,
        1,
        0xffff_ffff,
        0,
    ))
}

fn case_tx_duplicate_inputs() -> Satd {
    let op = OutPoint { txid: Txid::from_byte_array([0xab; 32]), vout: 0 };
    let dup = TxIn {
        previous_output: op,
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };
    tx(&Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![dup.clone(), dup],
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: bitcoin::ScriptBuf::new() }],
    })
}

fn case_coinbase_scriptsig_too_short() -> Satd {
    let mut cbtx = coinbase(1, 50_0000_0000);
    cbtx.input[0].script_sig = bitcoin::ScriptBuf::from(vec![0xff]); // 1 byte
    tx(&cbtx)
}

fn case_coinbase_scriptsig_too_long() -> Satd {
    let mut cbtx = coinbase(1, 50_0000_0000);
    cbtx.input[0].script_sig = bitcoin::ScriptBuf::from(vec![0xff; 101]); // 101 bytes
    tx(&cbtx)
}

fn case_non_coinbase_null_input() -> Satd {
    tx(&Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0xab; 32]), vout: 0 },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
        ],
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: bitcoin::ScriptBuf::new() }],
    })
}

// -- contextual / chain-level (connect_block) --

fn case_spend_nonexistent() -> Satd {
    let store = InMemoryStore::new();
    let fake = OutPoint { txid: Txid::from_byte_array([0xab; 32]), vout: 0 };
    let block = block_of(vec![coinbase(1, 50_0000_0000), spending_tx(fake, 50_000_000, 2, 0xffff_ffff, 0)]);
    connect(&store, &block, 1, 0)
}

fn case_immature_coinbase_spend() -> Satd {
    // coinbase coin at height 50, spent at height 149 (only 99 confirmations).
    let (store, op) = store_with_coin(50_000_000, 50, true);
    let block = block_of(vec![coinbase(149, block_subsidy(149)), spending_tx(op, 50_000_000, 2, 0xffff_ffff, 0)]);
    connect(&store, &block, 149, 0)
}

fn case_mature_coinbase_spend_ok() -> Satd {
    let (store, op) = store_with_coin(50_000_000, 50, true);
    let block = block_of(vec![coinbase(150, block_subsidy(150)), spending_tx(op, 50_000_000, 2, 0xffff_ffff, 0)]);
    connect(&store, &block, 150, 0)
}

fn case_inputs_below_outputs() -> Satd {
    let (store, op) = store_with_coin(50_000_000, 10, false);
    // Spend 50_000_000 but pay out 60_000_000.
    let block = block_of(vec![coinbase(60, block_subsidy(60)), spending_tx(op, 60_000_000, 2, 0xffff_ffff, 0)]);
    connect(&store, &block, 60, 0)
}

fn case_coinbase_value_too_high() -> Satd {
    // No fees; coinbase claims subsidy + 1.
    let store = InMemoryStore::new();
    let block = block_of(vec![coinbase(1, block_subsidy(1) + 1)]);
    connect(&store, &block, 1, 0)
}

fn case_bad_coinbase_height_bip34() -> Satd {
    // Coinbase encodes height 999 but the block is at height 1.
    let store = InMemoryStore::new();
    let block = block_of(vec![coinbase(999, block_subsidy(1))]);
    connect(&store, &block, 1, 0)
}

fn case_locktime_not_final() -> Satd {
    let (store, op) = store_with_coin(50_000_000, 10, false);
    // Height-based locktime 50, block at height 49, non-final sequence.
    let block = block_of(vec![coinbase(49, block_subsidy(49)), spending_tx(op, 50_000_000, 2, 0, 50)]);
    connect(&store, &block, 49, 0)
}

fn case_bip68_sequence_not_met() -> Satd {
    let (store, op) = store_with_coin(50_000_000, 50, false);
    // tx v2, sequence requires 10 blocks, coin at 50, block at 55.
    let block = block_of(vec![coinbase(55, block_subsidy(55)), spending_tx(op, 50_000_000, 2, 10, 0)]);
    connect(&store, &block, 55, 0)
}

/// Spend an output created earlier in the same block (valid ordering).
fn case_intra_block_spend_ok() -> Satd {
    let store = InMemoryStore::new();
    let cbtx = coinbase(1, block_subsidy(1));
    let cb_txid = cbtx.compute_txid();
    // The coinbase output is immature (height 1, spent at height 1), so to
    // get a clean accept we instead fund via a non-coinbase intermediate.
    // Pre-seed a spendable coin, spend it into `mid`, then spend `mid`.
    let (store2, op) = store_with_coin(50_000_000, 0, false);
    let mid = spending_tx(op, 50_000_000, 2, 0xffff_ffff, 0);
    let mid_txid = mid.compute_txid();
    let child = spending_tx(OutPoint { txid: mid_txid, vout: 0 }, 50_000_000, 2, 0xffff_ffff, 0);
    let _ = (store, cbtx, cb_txid);
    let block = block_of(vec![coinbase(1, block_subsidy(1)), mid, child]);
    connect(&store2, &block, 1, 0)
}

// -- proof-of-work / difficulty / timestamp (pow.rs) --

fn case_high_hash_bad_pow() -> Satd {
    // Hard (mainnet) target against an unsolved regtest header → fails PoW.
    let mut header = bitcoin::constants::genesis_block(Network::Regtest).header;
    header.bits = CompactTarget::from_consensus(0x1d00_ffff);
    header.nonce = 0;
    check_proof_of_work(&header).map_err(|e| e.to_string())
}

fn case_bad_diffbits() -> Satd {
    let prev = block_index_entry(0, BASE_TIME, REGTEST_POWLIMIT_BITS);
    let mut header = bitcoin::constants::genesis_block(Network::Regtest).header;
    header.bits = CompactTarget::from_consensus(0x1d00_ffff); // wrong for regtest
    check_difficulty(&header, &prev, Network::Regtest, |_| None).map_err(|e| e.to_string())
}

fn case_time_too_old_mtp() -> Satd {
    // 11 ancestors at increasing times; header at/below median → reject.
    let ancestors: Vec<BlockIndexEntry> =
        (1..=11).map(|h| block_index_entry(h, BASE_TIME + h * 100, REGTEST_POWLIMIT_BITS)).collect();
    let mut header = bitcoin::constants::genesis_block(Network::Regtest).header;
    header.time = BASE_TIME; // below the median of [BASE+100..BASE+1100]
    check_timestamp(&header, 12, |h| ancestors.iter().find(|e| e.height == h).cloned())
        .map_err(|e| e.to_string())
}

// -- GAPS: Core rejects, satd accepts --

fn case_gap_block_sigops() -> Satd {
    // Coinbase output packed with bare OP_CHECKMULTISIG (20 legacy sigops
    // each). 4001 ops → 80_020 sigop cost > MAX_BLOCK_SIGOPS_COST (80_000),
    // while staying far under MAX_BLOCK_WEIGHT. Core: `bad-blk-sigops`.
    let store = InMemoryStore::new();
    let script = bitcoin::ScriptBuf::from(vec![
        bitcoin::opcodes::all::OP_CHECKMULTISIG.to_u8();
        4001
    ]);
    let cbtx = coinbase_with_outputs(
        1,
        vec![TxOut { value: Amount::from_sat(0), script_pubkey: script }],
    );
    connect(&store, &block_of(vec![cbtx]), 1, 0)
}

fn case_gap_bip30() -> Satd {
    // A block whose spending tx creates an output whose (txid, 0) already
    // exists, unspent, in the UTXO set. Core: `bad-txns-BIP30`.
    let (store, op) = store_with_coin(50_000_000, 0, false);
    let spend = spending_tx(op, 50_000_000, 2, 0xffff_ffff, 0);
    let dup_txid = spend.compute_txid();
    // Pre-seed an unspent coin at the soon-to-be-created outpoint.
    let mut batch = StoreBatch::default();
    batch.coin_puts.push((
        OutPoint { txid: dup_txid, vout: 0 },
        Coin { amount: 1_000, script_pubkey: bitcoin::ScriptBuf::new(), height: 1, coinbase: false },
    ));
    store.write_batch(batch).unwrap();
    let block = block_of(vec![coinbase(200, block_subsidy(200)), spend]);
    connect(&store, &block, 200, 0)
}

fn case_gap_time_too_new() -> Satd {
    // Header timestamp 3 hours ahead of `now` → Core: `time-too-new`.
    // Now enforced by check_future_timestamp (2h slack).
    let mut header = bitcoin::constants::genesis_block(Network::Regtest).header;
    header.time = BASE_TIME + 3 * 60 * 60;
    check_future_timestamp(&header, BASE_TIME as u64).map_err(|e| e.to_string())
}

fn case_gap_block_version() -> Satd {
    // Block version 1 at a height where BIP34/66/65 are active → Core:
    // `bad-version(0x00000001)`. Now enforced by check_block_version.
    let mut b = block_of(vec![coinbase(1, block_subsidy(1))]);
    b.header.version = bitcoin::block::Version::from_consensus(1);
    b.header.merkle_root = b.compute_merkle_root().unwrap();
    check_block_version(&b.header, 1, Network::Regtest).map_err(|e| e.to_string())
}

// -- audit-discovered edge cases (deeper than feature_block.py) --

fn case_merkle_mutation_cve_2012_2459() -> Satd {
    // CVE-2012-2459: a block whose tx list ends in a duplicated subtree has
    // the SAME merkle root as the honest list, because the odd-node
    // duplication in `[cb, t1, t2]` produces the identical tree as the
    // explicit `[cb, t1, t2, t2]`. Core's CheckBlock computes a `mutated`
    // flag and rejects `bad-txns-duplicate`. Now enforced by check_block's
    // merkle_tree_mutated detector → exact match (was a Gap; satd previously
    // only caught the duplicate later in connect_block as a double-spend).
    let t1 = spending_tx(OutPoint { txid: Txid::from_byte_array([0x11; 32]), vout: 0 }, 1_000, 1, 0xffff_ffff, 0);
    let t2 = spending_tx(OutPoint { txid: Txid::from_byte_array([0x22; 32]), vout: 0 }, 1_000, 1, 0xffff_ffff, 0);
    let b = block_of(vec![coinbase(1, 50_0000_0000), t1, t2.clone(), t2]);
    cb(&b)
}

fn case_tx_oversize() -> Satd {
    // A single transaction whose no-witness serialized size * 4 exceeds
    // MAX_BLOCK_WEIGHT. Core's CheckTransaction rejects `bad-txns-oversize`.
    // Now enforced by check_transaction's per-tx weight cap → exact match (was
    // a Gap; in the block path the block-weight check already caught it, but a
    // standalone tx — e.g. sendrawtransaction — previously slipped through).
    let big = bitcoin::ScriptBuf::from(vec![0x00; 1_100_000]); // ~1.1 MB; *4 > 4 M WU
    let t = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0xab; 32]), vout: 0 },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: big }],
    };
    tx(&t)
}

// ── The matrix ────────────────────────────────────────────────────────

fn cases() -> Vec<Case> {
    use Core::*;
    use Expect::*;
    vec![
        // context-free block structure
        Case { name: "accept_genesis", core: Accept, expect: Match, run: case_accept_genesis },
        Case { name: "empty_block", core: Reject("bad-blk-length"), expect: Match, run: case_empty_block },
        Case { name: "first_tx_not_coinbase", core: Reject("bad-cb-missing"), expect: Match, run: case_first_tx_not_coinbase },
        Case { name: "multiple_coinbase", core: Reject("bad-cb-multiple"), expect: Match, run: case_multiple_coinbase },
        Case { name: "bad_merkle_root", core: Reject("bad-txnmrklroot"), expect: Match, run: case_bad_merkle_root },
        Case { name: "oversize_block", core: Reject("bad-blk-length"), expect: Match, run: case_oversize_block },
        Case { name: "witness_commitment_missing", core: Reject("bad-witness-merkle-match"), expect: Match, run: case_witness_commitment_missing },
        // context-free transaction
        Case { name: "tx_no_inputs", core: Reject("bad-txns-vin-empty"), expect: Match, run: case_tx_no_inputs },
        Case { name: "tx_no_outputs", core: Reject("bad-txns-vout-empty"), expect: Match, run: case_tx_no_outputs },
        Case { name: "tx_output_over_max", core: Reject("bad-txns-vout-toolarge"), expect: Match, run: case_tx_output_over_max },
        Case { name: "tx_duplicate_inputs", core: Reject("bad-txns-inputs-duplicate"), expect: Match, run: case_tx_duplicate_inputs },
        Case { name: "coinbase_scriptsig_too_short", core: Reject("bad-cb-length"), expect: Match, run: case_coinbase_scriptsig_too_short },
        Case { name: "coinbase_scriptsig_too_long", core: Reject("bad-cb-length"), expect: Match, run: case_coinbase_scriptsig_too_long },
        Case { name: "non_coinbase_null_input", core: Reject("bad-txns-prevout-null"), expect: Match, run: case_non_coinbase_null_input },
        // contextual / chain-level
        Case { name: "spend_nonexistent", core: Reject("bad-txns-inputs-missingorspent"), expect: Match, run: case_spend_nonexistent },
        Case { name: "immature_coinbase_spend", core: Reject("bad-txns-premature-spend-of-coinbase"), expect: Match, run: case_immature_coinbase_spend },
        Case { name: "mature_coinbase_spend_ok", core: Accept, expect: Match, run: case_mature_coinbase_spend_ok },
        Case { name: "inputs_below_outputs", core: Reject("bad-txns-in-belowout"), expect: Match, run: case_inputs_below_outputs },
        Case { name: "coinbase_value_too_high", core: Reject("bad-cb-amount"), expect: Match, run: case_coinbase_value_too_high },
        Case { name: "bad_coinbase_height_bip34", core: Reject("bad-cb-height"), expect: Match, run: case_bad_coinbase_height_bip34 },
        Case { name: "locktime_not_final", core: Reject("bad-txns-nonfinal"), expect: Match, run: case_locktime_not_final },
        Case { name: "bip68_sequence_not_met", core: Reject("bad-txns-nonBIP68-final"), expect: Match, run: case_bip68_sequence_not_met },
        Case { name: "intra_block_spend_ok", core: Accept, expect: Match, run: case_intra_block_spend_ok },
        // proof-of-work / difficulty / timestamp
        Case { name: "high_hash_bad_pow", core: Reject("high-hash"), expect: Match, run: case_high_hash_bad_pow },
        Case { name: "bad_diffbits", core: Reject("bad-diffbits"), expect: Match, run: case_bad_diffbits },
        Case { name: "time_too_old_mtp", core: Reject("time-too-old"), expect: Match, run: case_time_too_old_mtp },
        // Formerly gaps (Core rejects, satd accepted) — now enforced and
        // promoted to exact matches by the consensus fixes in this PR.
        Case { name: "block_sigops", core: Reject("bad-blk-sigops"), expect: Match, run: case_gap_block_sigops },
        Case { name: "bip30_duplicate_txid", core: Reject("bad-txns-BIP30"), expect: Match, run: case_gap_bip30 },
        Case { name: "time_too_new", core: Reject("time-too-new"), expect: Match, run: case_gap_time_too_new },
        Case { name: "block_version", core: Reject("bad-version(0x00000001)"), expect: Match, run: case_gap_block_version },
        // Audit-discovered gaps (block-handling equivalence audit, findings A
        // and F) — now enforced and promoted to exact matches: merkle-mutation
        // detection in check_block and a per-tx weight cap in check_transaction.
        Case { name: "merkle_mutation_cve_2012_2459", core: Reject("bad-txns-duplicate"), expect: Match, run: case_merkle_mutation_cve_2012_2459 },
        Case { name: "tx_oversize", core: Reject("bad-txns-oversize"), expect: Match, run: case_tx_oversize },
    ]
}

// ── Runner ────────────────────────────────────────────────────────────

/// Classify one case's observed satd outcome against Core + the declared
/// expectation. Returns `Ok(status_line)` on agreement, `Err(failure)` on
/// a regression / closed-gap that must be acted on.
fn classify(case: &Case, satd: &Satd) -> Result<String, String> {
    let core_reason = match case.core {
        Core::Accept => None,
        Core::Reject(r) => Some(r),
    };
    match (case.expect, core_reason, satd) {
        // satd matches Core exactly.
        (Expect::Match, None, Ok(())) => Ok(format!("✓ {:<32} accept == Core", case.name)),
        (Expect::Match, Some(r), Err(e)) if e == r => {
            Ok(format!("✓ {:<32} reject({r}) == Core", case.name))
        }
        (Expect::Match, Some(r), Err(e)) => Err(format!(
            "REGRESSION {}: expected Core reason `{r}`, satd rejected with `{e}`",
            case.name
        )),
        (Expect::Match, Some(r), Ok(())) => Err(format!(
            "REGRESSION {}: Core rejects `{r}` but satd ACCEPTED",
            case.name
        )),
        (Expect::Match, None, Err(e)) => {
            Err(format!("REGRESSION {}: Core accepts but satd rejected `{e}`", case.name))
        }

        // both reject, satd uses a different reason label.
        (Expect::ReasonDiffers(s), Some(r), Err(e)) if e == s => {
            Ok(format!("~ {:<32} reject({e}) [Core: {r}]", case.name))
        }
        (Expect::ReasonDiffers(s), Some(_), Err(e)) => Err(format!(
            "DRIFT {}: expected satd reason `{s}`, got `{e}` — update the matrix",
            case.name
        )),
        (Expect::ReasonDiffers(s), Some(_), Ok(())) => Err(format!(
            "GAP OPENED {}: satd used to reject `{s}`, now ACCEPTS — regression",
            case.name
        )),
        (Expect::ReasonDiffers(_), None, _) => {
            Err(format!("BAD CASE {}: ReasonDiffers requires Core::Reject", case.name))
        }

        // known gap: Core rejects, satd accepts.
        (Expect::Gap, Some(r), Ok(())) => {
            Ok(format!("⚠ {:<32} GAP open (Core: {r}, satd accepts)", case.name))
        }
        (Expect::Gap, Some(r), Err(e)) => Err(format!(
            "GAP CLOSED {}: satd now rejects with `{e}` (Core: {r}). \
             Promote this case to Expect::Match (or ReasonDiffers) and remove it from the gap list.",
            case.name
        )),
        (Expect::Gap, None, _) => Err(format!("BAD CASE {}: Gap requires Core::Reject", case.name)),
    }
}

#[test]
fn feature_block_consensus_matrix() {
    let cases = cases();
    let mut report = String::from("\nfeature_block.py differential matrix (satd vs Bitcoin Core)\n");
    let mut failures = Vec::new();
    let (mut matched, mut reason_diff, mut gaps) = (0u32, 0u32, 0u32);

    for case in &cases {
        let satd = (case.run)();
        match classify(case, &satd) {
            Ok(line) => {
                match case.expect {
                    Expect::Match => matched += 1,
                    Expect::ReasonDiffers(_) => reason_diff += 1,
                    Expect::Gap => gaps += 1,
                }
                report.push_str(&line);
                report.push('\n');
            }
            Err(f) => {
                report.push_str(&format!("✗ {f}\n"));
                failures.push(f);
            }
        }
    }

    report.push_str(&format!(
        "\n{} cases: {matched} exact-match, {reason_diff} reason-differs, {gaps} known-gap, {} failures\n",
        cases.len(),
        failures.len()
    ));
    // Always print the matrix (visible with `cargo test -- --nocapture`).
    println!("{report}");

    assert!(
        failures.is_empty(),
        "feature_block differential matrix drifted:\n{}",
        failures.join("\n")
    );
}
