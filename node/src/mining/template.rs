use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::{BlockHash, Transaction};

use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;

/// Confirmations a coinbase output needs before it can be spent (Core's
/// `COINBASE_MATURITY`). Duplicated from `chain::connect`, which keeps it
/// private to the consensus path.
const COINBASE_MATURITY: u32 = 100;

/// The consensus maximum block weight (Core's `MAX_BLOCK_WEIGHT`, 4 million
/// weight units): what a block may weigh, and the ceiling `-blockmaxweight`
/// may not exceed.
pub const MAX_BLOCK_WEIGHT: usize = 4_000_000;
/// Reserve weight for coinbase transaction. Matches Bitcoin Core v30's
/// `DEFAULT_BLOCK_RESERVED_WEIGHT` (8000 WU).
pub(crate) const COINBASE_WEIGHT_RESERVE: usize = 8_000;
/// The block sigop-cost limit `connect_block` enforces (`bad-blk-sigops`),
/// Core's `MAX_BLOCK_SIGOPS_COST` (`src/consensus/consensus.h`).
const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;
/// Sigop cost set aside for the coinbase, Core's
/// `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS` (`src/policy/policy.h`).
/// The Stratum server's coinbase costs at most 4 — one legacy sigop, for a
/// P2PKH payout (`stratum::template` tests every payout type).
pub(crate) const COINBASE_SIGOPS_RESERVE: u64 = 400;

/// A selected transaction for the block template.
#[derive(Clone)]
pub struct TemplateTx {
    pub tx: Transaction,
    pub fee: u64,
    pub weight: usize,
    /// Signature-operation cost, counted as `connect_block` counts it.
    pub sigop_cost: u64,
}

/// Block template ready for mining.
/// Statistics of the most recently assembled block template.
///
/// `getmininginfo` reports `currentblocktx` / `currentblockweight` from the
/// last template that was actually built, and omits both fields when none has
/// been. Core keeps exactly these two values as statics on `BlockAssembler`
/// (`m_last_block_num_txs` / `m_last_block_weight`, set at the end of
/// `CreateNewBlock`) — deliberately, so that reporting them costs nothing.
/// Assembling a fresh template per `getmininginfo` call would walk the mempool
/// on a hot, `Read`-classified RPC that monitoring polls.
///
/// `u64::MAX` is the "no template assembled yet" sentinel.
static LAST_BLOCK_NUM_TXS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);
static LAST_BLOCK_WEIGHT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);

/// The last assembled template's transaction count and weight, or `None` when
/// no template has been assembled since startup.
pub fn last_block_stats() -> Option<(u64, u64)> {
    use std::sync::atomic::Ordering;
    let txs = LAST_BLOCK_NUM_TXS.load(Ordering::Relaxed);
    let weight = LAST_BLOCK_WEIGHT.load(Ordering::Relaxed);
    (txs != u64::MAX && weight != u64::MAX).then_some((txs, weight))
}

#[derive(Clone)]
pub struct BlockTemplate {
    pub version: i32,
    pub prev_hash: BlockHash,
    pub height: u32,
    pub bits: CompactTarget,
    pub cur_time: u32,
    /// The earliest timestamp a block on this template may carry: the
    /// median time past of the tip, plus one (Core's `mintime`).
    pub min_time: u32,
    pub transactions: Vec<TemplateTx>,
    pub coinbase_value: u64,
}

/// Create a block template from the current chain state and mempool.
///
/// Assembly is a long read: the tip, the tip's index entry, the MTP, the
/// mempool snapshot, and one UTXO lookup per input of every candidate, across a
/// multi-pass selection loop. Nothing in that sequence pins the chain, so a
/// block connecting part-way through is seen by some reads and not others.
///
/// That is not merely a stale template. Take a mempool holding parent X and
/// child T. Assembly starts on tip H; mid-loop a block mines X. T is deferred
/// on the first pass because X was in the `in_mempool` snapshot, but on a later
/// pass `get_coin` now resolves X's output from the post-connect UTXO set, so T
/// is included -- while X itself is excluded (it is no longer in the mempool).
/// The emitted template builds on H, where X is unconfirmed, so the block is
/// `bad-txns-inputs-missingorspent`. A miner that wins the race at the
/// contested height submits an invalid block instead of a valid competing one.
///
/// So: assemble against a chainstate that held still, and rebuild if it did
/// not. `coherent_read` is what decides that, rather than a `tip_snapshot()`
/// on each side -- a connect publishes its coins at the store commit and moves
/// the tip a moment later, and in between, the tip is unchanged while
/// `get_coin` already answers from the new block. That is precisely the
/// X-and-T case above, so the check has to cover the window rather than just
/// the tip.
///
/// If the chain is moving faster than the node can assemble, fall back to a
/// coinbase-only template -- less profitable for one poll, but a template with
/// no transactions has no cross-chain inconsistency available to it.
/// The `-blockmintxfee` floor, in sat/kvB. A package whose feerate is below it
/// is left out of the template.
///
/// Restart-only (`satd/src/reload.rs`), so a process-wide value set once at
/// startup is a faithful model of the option and keeps it out of eight mining
/// function signatures. `create_template_with_floor` takes it explicitly for
/// tests, which must not depend on — or disturb — process state.
static BLOCK_MIN_TX_FEE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(DEFAULT_BLOCK_MIN_TX_FEE);

/// Core's `DEFAULT_BLOCK_MIN_TX_FEE`, in sat/kvB.
///
/// One satoshi per kvB, three orders of magnitude below the default relay
/// floor, and deliberately so: the floor exists to keep a template from being
/// padded with transactions that pay *nothing*, not to second-guess the relay
/// policy. Defaulting it to the relay floor instead would silently strand
/// every transaction on any node whose `-minrelaytxfee` is lower — the
/// mempool would accept them and the template would never mine them.
pub const DEFAULT_BLOCK_MIN_TX_FEE: u64 = 1;

/// Core's regtest-only `-blockversion=<n>` override, or `i64::MIN` for "not
/// set" — the sentinel keeps this a lock-free atomic while still allowing a
/// caller to ask for version 0.
static BLOCK_VERSION_OVERRIDE: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(i64::MIN);

/// Record the configured `-blockversion`. Called once during startup; a
/// `None` leaves the computed version in place.
///
/// Core applies it only when `MineBlocksOnDemand()` — regtest — so the caller
/// is responsible for not passing one on any other network.
pub fn set_block_version_override(version: Option<i64>) {
    BLOCK_VERSION_OVERRIDE.store(
        version.unwrap_or(i64::MIN),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Record the configured `-blockmintxfee`. Called once during startup.
pub fn set_block_min_tx_fee(rate: u64) {
    BLOCK_MIN_TX_FEE.store(rate, std::sync::atomic::Ordering::Relaxed);
}

/// The configured `-blockmintxfee`.
pub fn block_min_tx_fee() -> u64 {
    BLOCK_MIN_TX_FEE.load(std::sync::atomic::Ordering::Relaxed)
}

/// The `-blockmaxweight` cap on a template, the coinbase reserve included.
///
/// Restart-only, like `-blockmintxfee`, so it is a process-wide value set once
/// at startup (see [`BLOCK_MIN_TX_FEE`]). Defaults to Core's
/// `DEFAULT_BLOCK_MAX_WEIGHT`, which is the consensus maximum
/// (`src/policy/policy.h`).
static BLOCK_MAX_WEIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(MAX_BLOCK_WEIGHT);

/// Record the configured `-blockmaxweight`. Called once during startup;
/// returns the value applied.
///
/// Clamped to `[COINBASE_WEIGHT_RESERVE, MAX_BLOCK_WEIGHT]` as Core's
/// `BlockAssembler` clamps `nBlockMaxWeight` to `[block_reserved_weight,
/// MAX_BLOCK_WEIGHT]` (`ClampOptions`, `src/node/miner.cpp`). A cap below the
/// reserve leaves no room for a transaction, so the template is coinbase-only.
/// A value above the consensus maximum never reaches here: the config refuses
/// it at startup with Core's message.
pub fn set_block_max_weight(weight: usize) -> usize {
    let applied = clamp_block_max_weight(weight);
    BLOCK_MAX_WEIGHT.store(applied, std::sync::atomic::Ordering::Relaxed);
    applied
}

/// Core's clamp on `-blockmaxweight`; see [`set_block_max_weight`].
pub fn clamp_block_max_weight(weight: usize) -> usize {
    weight.clamp(COINBASE_WEIGHT_RESERVE, MAX_BLOCK_WEIGHT)
}

/// The configured `-blockmaxweight`, clamped.
pub fn block_max_weight() -> usize {
    BLOCK_MAX_WEIGHT.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn create_template(chain_state: &ChainState, mempool: &Mempool) -> BlockTemplate {
    create_template_with_limits(chain_state, mempool, block_min_tx_fee(), block_max_weight())
}

/// A template with no transactions on the current tip: always valid, since
/// there is nothing in it to be wrong. What the Stratum server hands out while
/// the node's own templates are failing their validity check.
pub fn create_coinbase_only_template(chain_state: &ChainState, mempool: &Mempool) -> BlockTemplate {
    assemble_template(chain_state, mempool, false, block_min_tx_fee(), block_max_weight())
}

/// [`create_template`] with an explicit `-blockmintxfee` floor.
pub fn create_template_with_floor(
    chain_state: &ChainState,
    mempool: &Mempool,
    block_min_tx_fee: u64,
) -> BlockTemplate {
    create_template_with_limits(chain_state, mempool, block_min_tx_fee, block_max_weight())
}

/// [`create_template`] with an explicit `-blockmintxfee` floor and
/// `-blockmaxweight` cap, so tests need not depend on, or disturb, the
/// process-wide values.
pub fn create_template_with_limits(
    chain_state: &ChainState,
    mempool: &Mempool,
    block_min_tx_fee: u64,
    block_max_weight: usize,
) -> BlockTemplate {
    if let Some(template) = chain_state.coherent_read(|| {
        assemble_template(chain_state, mempool, true, block_min_tx_fee, block_max_weight)
    }) {
        return template;
    }
    tracing::warn!(
        target: "mining::template",
        "chain advanced during every template assembly attempt; \
         emitting a coinbase-only template rather than one assembled across two chains"
    );
    assemble_template(chain_state, mempool, false, block_min_tx_fee, block_max_weight)
}

/// One assembly pass. `include_mempool` false yields a coinbase-only template.
fn assemble_template(
    chain_state: &ChainState,
    mempool: &Mempool,
    include_mempool: bool,
    block_min_tx_fee: u64,
    block_max_weight: usize,
) -> BlockTemplate {
    let tip_hash = chain_state.tip_hash();
    let tip_entry = chain_state.get_block_index(&tip_hash).unwrap();
    let height = tip_entry.height + 1;
    let subsidy = crate::chain::connect::block_subsidy(chain_state.network, height);

    // The (height, MTP) this block will be validated under — the MTP
    // context of `height` is the 11 blocks strictly below it, i.e. the
    // tip's MTP.
    let template_mtp = chain_state.get_median_time_past(height);

    // Template assembly is scope-filtered: transactions quarantined `on
    // template` are held but never mined by this node (design §2.4/§3), so
    // they are not candidates.
    let entries = if include_mempool { mempool.get_template_entries() } else { Vec::new() };
    let Selection { transactions, total_weight, total_fees } = select_transactions(
        chain_state,
        entries,
        height,
        template_mtp,
        block_min_tx_fee,
        block_max_weight,
    );

    // Timestamp: max of current time and MTP + 1. Core's `UpdateTime` uses
    // `max(GetAdjustedTime(), pindexPrev->GetMedianTimePast() + 1)` — the
    // median-time-past floor ensures the block satisfies the consensus
    // `time-too-old` check without the miner having to care about MTP.
    //
    // Reads the node clock, not the system one, so a mocked chain mines at the
    // mocked time — which is how Core's tests get deterministic block
    // timestamps.
    //
    // Clamp before the narrowing cast. `setmocktime` accepts anything up to
    // i64::MAX/1e9 (Core's range), so a mock above u32::MAX would otherwise
    // *wrap*: 6_094_967_296 truncates to 1_800_000_000, the block is stamped in
    // 2027, the future-block check compares against the untruncated mock and
    // passes, and the block is accepted. Clearing the mock then leaves a
    // datadir whose tip is decades ahead, so every subsequent template is
    // `MTP + 1` — rejected as time-too-new — until real time catches up.
    // Saturating keeps the value in range so the future-block check can do its
    // job on it.
    let now = u32::try_from(crate::time::now_secs()).unwrap_or(u32::MAX);
    let min_time = template_mtp + 1;
    let mut cur_time = std::cmp::max(now, min_time);
    // BIP 94 (testnet4): the first block of a retarget period may not be
    // stamped more than 600 s before its parent. Core's `UpdateTime` lifts the
    // timestamp to that floor; without it a node whose clock trails the tip
    // builds a template that fails `check_difficulty` as a timewarp.
    if chain_state.network == bitcoin::Network::Testnet4
        && height.is_multiple_of(crate::validation::pow::RETARGET_INTERVAL)
    {
        cur_time = cur_time.max(tip_entry.header.time.saturating_sub(600));
    }

    // Difficulty for a block at `cur_time` on this tip — the same computation
    // `check_difficulty` compares a received block against, so a template is
    // valid at a retarget boundary. On testnet3/testnet4 the answer depends on
    // the timestamp (the 20-minute minimum-difficulty rule), which is why it
    // is computed after `cur_time` is fixed. The height index is the active
    // chain, and the tip is on it, so its rows are this template's ancestors.
    //
    // A failure means an ancestor the node should hold is missing. Reusing
    // the tip's bits keeps the template well-formed; the block it yields is
    // judged by `accept_block`, which fails closed on the same missing entry.
    let bits = crate::validation::pow::next_bits(
        chain_state.network,
        &tip_entry,
        cur_time,
        |h| chain_state.get_block_index(&chain_state.get_block_hash_by_height(h)?),
        |hash| chain_state.get_block_index(hash),
    )
    .unwrap_or_else(|e| {
        tracing::warn!(
            target: "mining::template",
            height,
            error = %e,
            "cannot compute the difficulty for the next block; using the tip's bits"
        );
        tip_entry.header.bits
    });

    // Core sets these at the end of `CreateNewBlock`; `getmininginfo`

    // reads them instead of assembling a template of its own.

    LAST_BLOCK_NUM_TXS.store(transactions.len() as u64, std::sync::atomic::Ordering::Relaxed);

    LAST_BLOCK_WEIGHT.store(total_weight as u64, std::sync::atomic::Ordering::Relaxed);


    // `-blockversion` overrides the computed version on regtest only, as
    // Core's `CreateNewBlock` does under `MineBlocksOnDemand()`.
    let version = match BLOCK_VERSION_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
        i64::MIN => 0x20000000u32 as i32, // BIP 9 version bits
        v => v as i32,
    };

    BlockTemplate {
        version,
        prev_hash: tip_hash,
        height,
        bits,
        cur_time,
        min_time,
        transactions,
        coinbase_value: subsidy + total_fees,
    }
}

/// Absolute finality for a block at `height` whose MTP context is `mtp` —
/// the rule `connect_block` enforces (Core's `IsFinalTx`): final iff the
/// locktime is zero, *strictly* below the cutoff (height for height
/// locktimes, MTP for time locktimes), or every input's sequence is
/// SEQUENCE_FINAL.
fn tx_is_final_at(tx: &Transaction, height: u32, mtp: u32) -> bool {
    let locktime = tx.lock_time.to_consensus_u32();
    if locktime == 0 {
        return true;
    }
    let cutoff = if locktime < 500_000_000 { height } else { mtp };
    if locktime < cutoff {
        return true;
    }
    tx.input
        .iter()
        .all(|i| i.sequence == bitcoin::Sequence::MAX)
}

/// Compute merkle root from a list of 32-byte hashes.
fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    let mut current = hashes.to_vec();
    while current.len() > 1 {
        if !current.len().is_multiple_of(2) {
            let last = *current.last().unwrap();
            current.push(last);
        }
        let mut next = Vec::new();
        for i in (0..current.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&current[i]);
            combined[32..].copy_from_slice(&current[i + 1]);
            let hash = bitcoin::hashes::sha256d::Hash::hash(&combined);
            next.push(hash.to_byte_array());
        }
        current = next;
    }
    current[0]
}

/// Compute the default witness commitment hex for a block template.
/// Returns the full OP_RETURN script hex (6a24aa21a9ed + 32-byte commitment).
///
/// Computed even when no transaction carries witness data: Core emits a
/// commitment for every post-segwit template (a witness-free template still
/// has a well-defined witness root — wtxid == txid for legacy transactions,
/// and the coinbase slot is zeroed), and external mining software trusts the
/// field rather than computing its own (#548).
pub fn compute_witness_commitment_hex(txs: &[TemplateTx]) -> String {
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(&compute_witness_commitment(txs));
    hex::encode(script)
}

/// The 32-byte witness commitment for a block holding a coinbase followed by
/// `txs`, with an all-zero witness reserved value:
/// `SHA256d(witness_merkle_root || [0; 32])`.
pub fn compute_witness_commitment(txs: &[TemplateTx]) -> [u8; 32] {
    // Coinbase wtxid = 0x00...00, then wtxids of included transactions
    let mut hashes: Vec<[u8; 32]> = vec![[0u8; 32]];
    for ttx in txs {
        hashes.push(ttx.tx.compute_wtxid().to_raw_hash().to_byte_array());
    }
    let witness_root = merkle_root(&hashes);

    // commitment = SHA256d(witness_root || witness_nonce)
    let witness_nonce = [0u8; 32];
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&witness_root);
    preimage[32..].copy_from_slice(&witness_nonce);
    bitcoin::hashes::sha256d::Hash::hash(&preimage).to_byte_array()
}

/// Core's `MAX_CONSECUTIVE_FAILURES` (`src/node/miner.cpp`, v30.0:318): once
/// the block is within [`BLOCK_FULL_ENOUGH_WEIGHT_DELTA`] of its cap, this many
/// packages in a row that do not fit end the selection.
const MAX_CONSECUTIVE_FAILURES: usize = 1000;

/// Core's `BLOCK_FULL_ENOUGH_WEIGHT_DELTA` (`src/node/miner.cpp`, v30.0:319):
/// how close to its cap a block must be before a run of failures ends the
/// selection. Core v29 used the coinbase reserve here (`nBlockWeight >
/// nBlockMaxWeight - block_reserved_weight`); v30 made it a fixed 4,000 WU.
const BLOCK_FULL_ENOUGH_WEIGHT_DELTA: usize = 4_000;

/// The transactions [`select_transactions`] chose, in block order, and the
/// totals the template reports.
struct Selection {
    transactions: Vec<TemplateTx>,
    /// Including the coinbase reserve.
    total_weight: usize,
    /// Actual fees (not `prioritisetransaction`-modified): what the coinbase
    /// may claim.
    total_fees: u64,
}

/// A candidate's package: itself plus its in-mempool ancestors not yet in the
/// block. Core's `CTxMemPoolModifiedEntry` state (`nSizeWithAncestors`,
/// `nModFeesWithAncestors`, `nSigOpCostWithAncestors`), kept for every
/// candidate rather than only the modified ones.
#[derive(Clone, Copy)]
struct Package {
    /// Modified fee (fee + `fee_delta`, floored at zero per transaction).
    fee: u64,
    weight: u64,
    sigops: u64,
}

/// A heap key: a candidate's package score when it was pushed. `version`
/// matches the candidate's current version only while its package is
/// unchanged; a stale key is skipped when popped.
struct Ranked {
    fee: u64,
    weight: u64,
    txid: bitcoin::Txid,
    idx: usize,
    version: u32,
}

impl PartialEq for Ranked {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}
impl Eq for Ranked {}
impl PartialOrd for Ranked {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Ranked {
    /// Higher package feerate is greater. Ties go to the smaller txid, as in
    /// Core's `CompareTxMemPoolEntryByAncestorFee` (`src/txmempool.h`), so the
    /// result does not depend on hash-map iteration order.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = self.fee as u128 * other.weight as u128;
        let b = other.fee as u128 * self.weight as u128;
        a.cmp(&b)
            .then_with(|| other.txid.cmp(&self.txid))
            .then_with(|| other.version.cmp(&self.version))
    }
}

/// Choose the block's transactions: Bitcoin Core's ancestor-score package
/// selection (`BlockAssembler::addPackageTxs`, `src/node/miner.cpp` in v29.0,
/// lines 299-438, the algorithm Core used until cluster mempool).
///
/// Every candidate is ranked by the feerate of its *package* — itself plus its
/// in-mempool ancestors not yet in the block — and the best package goes in
/// whole, ancestors first. A child paying for a cheap parent (CPFP, a
/// Lightning anchor, a zero-fee ephemeral-dust parent) therefore lifts the
/// parent in with it, where ranking each transaction by its own feerate left
/// the child waiting on a parent that never made the cut. After a package goes
/// in, each of its in-mempool descendants drops the included transactions from
/// its own package and is re-ranked (Core's `UpdatePackagesForAdded`).
///
/// A package is skipped when it would bring the block to its weight cap
/// (`block_max_weight`, `-blockmaxweight`) or its sigop limit, or past either:
/// Core refuses on `>=` for both, with the coinbase's reserves counted from the
/// start (`TestPackage`, v29.0:206-217; `TestChunkBlockLimits` since). A run of
/// [`MAX_CONSECUTIVE_FAILURES`] such packages ends the selection once the block
/// is within [`BLOCK_FULL_ENOUGH_WEIGHT_DELTA`] of the cap (v30.0:398-404).
/// Selection also stops at the first package paying less than
/// `-blockmintxfee` — it is the best one left, so nothing after it pays more
/// (v29.0:381-384).
///
/// Whether a transaction can be in this block at all does not change as
/// others are chosen, so it is decided once, up front: it must be final at
/// (`height`, `template_mtp`) and every input must resolve to a mature
/// confirmed coin whose BIP 68 lock is satisfied, or to another candidate
/// (which the package brings along). A transaction that fails, and everything
/// that spends it, is never a candidate (#588/#589). Core applies the finality
/// half per package (`TestPackageTransactions`); the rest it gets from its
/// mempool's own invariants, which satd re-checks here because a reorg or a
/// persisted mempool can hold a transaction admission never re-judged.
fn select_transactions(
    chain_state: &ChainState,
    entries: Vec<(bitcoin::Txid, crate::mempool::pool::MempoolEntry)>,
    height: u32,
    template_mtp: u32,
    block_min_tx_fee: u64,
    block_max_weight: usize,
) -> Selection {
    use std::collections::{BinaryHeap, HashMap};

    let n = entries.len();
    let index: HashMap<bitcoin::Txid, usize> =
        entries.iter().enumerate().map(|(i, (txid, _))| (*txid, i)).collect();

    // Parents among the candidates, and whether each candidate can be mined
    // at all if its parents are.
    let mut parents: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut minable = vec![true; n];
    for (i, (_, entry)) in entries.iter().enumerate() {
        if !tx_is_final_at(&entry.tx, height, template_mtp) {
            minable[i] = false;
            continue;
        }
        let bip68_enforced = (entry.tx.version.0 as u32) >= 2;
        for input in &entry.tx.input {
            let parent = input.previous_output.txid;
            // Resolve against the candidates first, then the UTXO set. A
            // parent that is neither — evicted after this child was admitted,
            // or held in quarantine `on template` — cannot be in this block,
            // and treating it as confirmed would mine an orphan
            // (bad-txns-inputs-missingorspent).
            let prev_height = if let Some(&p) = index.get(&parent) {
                if p != i && !parents[i].contains(&p) {
                    parents[i].push(p);
                    children[p].push(i);
                }
                // Born in this block.
                height
            } else if let Some(coin) = chain_state.get_coin(&input.previous_output) {
                // Coinbase maturity and BIP 68 are re-checked for the same
                // reason finality is: admission judged them against the tip
                // it saw. `connect_block` answers
                // bad-txns-premature-spend-of-coinbase for the whole block.
                if coin.coinbase && height - coin.height < COINBASE_MATURITY {
                    minable[i] = false;
                    break;
                }
                coin.height
            } else {
                minable[i] = false;
                break;
            };
            if bip68_enforced
                && !Mempool::bip68_satisfied(chain_state, input.sequence.0, prev_height, height, template_mtp)
            {
                minable[i] = false;
                break;
            }
        }
    }

    // Topological order (Kahn). A candidate left out — only a cycle, which a
    // valid mempool cannot hold — is never mined.
    let mut pending: Vec<usize> = parents.iter().map(Vec::len).collect();
    let mut order: Vec<usize> = (0..n).filter(|&i| pending[i] == 0).collect();
    let mut head = 0;
    while head < order.len() {
        let i = order[head];
        head += 1;
        for &c in &children[i] {
            pending[c] -= 1;
            if pending[c] == 0 {
                order.push(c);
            }
        }
    }
    let mut ordered = vec![false; n];
    for &i in &order {
        ordered[i] = true;
    }

    // Ancestor sets, and unminability passed down to every descendant.
    let mut ancestors: Vec<Vec<usize>> = vec![Vec::new(); n];
    for &i in &order {
        let mut set: Vec<usize> = Vec::new();
        for &p in &parents[i] {
            if !minable[p] {
                minable[i] = false;
            }
            set.push(p);
            set.extend_from_slice(&ancestors[p]);
        }
        set.sort_unstable();
        set.dedup();
        ancestors[i] = set;
    }
    for i in 0..n {
        if !ordered[i] {
            minable[i] = false;
        }
    }

    let own = |i: usize| -> Package {
        let e = &entries[i].1;
        Package {
            fee: (e.fee as i64).saturating_add(e.fee_delta).max(0) as u64,
            weight: e.weight as u64,
            sigops: e.sigop_cost,
        }
    };
    let mut package: Vec<Package> = (0..n)
        .map(|i| {
            let mut p = own(i);
            for &a in &ancestors[i] {
                let q = own(a);
                p.fee = p.fee.saturating_add(q.fee);
                p.weight = p.weight.saturating_add(q.weight);
                p.sigops = p.sigops.saturating_add(q.sigops);
            }
            p
        })
        .collect();

    let mut version = vec![0u32; n];
    let mut heap: BinaryHeap<Ranked> = (0..n)
        .filter(|&i| minable[i])
        .map(|i| Ranked { fee: package[i].fee, weight: package[i].weight, txid: entries[i].0, idx: i, version: 0 })
        .collect();

    let mut in_block = vec![false; n];
    let mut selected: Vec<usize> = Vec::new();
    let mut total_weight = COINBASE_WEIGHT_RESERVE;
    // Weight is not the only block limit. A mempool dense in sigops (bare
    // multisig outputs count 20 each) fills 80,000 in a fraction of a block's
    // weight, and a template that crosses it is a block `connect_block`
    // refuses as `bad-blk-sigops`. Core's `BlockAssembler` starts from the
    // coinbase's reserve and refuses a package that would bring the total to
    // the limit or past it (`>=`).
    let mut total_sigops = COINBASE_SIGOPS_RESERVE;
    let mut consecutive_failed = 0usize;
    // Descendant walks mark what they have visited with the walk's number.
    let mut visited = vec![0u32; n];
    let mut walk = 0u32;

    while let Some(top) = heap.pop() {
        let i = top.idx;
        if in_block[i] || top.version != version[i] {
            continue;
        }
        let pkg = package[i];
        // `-blockmintxfee`, on the package: a zero-fee parent rides in on its
        // child's fee, and only a package paying nothing is left out. This is
        // the best package left, so nothing after it clears the floor either.
        if block_min_tx_fee > 0
            && crate::mempool::policy::fee_rate_sat_per_kvb(pkg.fee, pkg.weight) < block_min_tx_fee
        {
            break;
        }
        // Both limits refuse a package that would *reach* them, not only one
        // that would pass them: Core's `TestChunkBlockLimits` tests `>=`, so
        // the heaviest template it builds is one weight unit under the cap.
        if total_weight as u64 + pkg.weight >= block_max_weight as u64
            || total_sigops.saturating_add(pkg.sigops) >= MAX_BLOCK_SIGOPS_COST
        {
            // Not failed for good: if an ancestor goes in with another
            // package, this one shrinks and is ranked again.
            consecutive_failed += 1;
            if consecutive_failed > MAX_CONSECUTIVE_FAILURES
                && total_weight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > block_max_weight
            {
                break;
            }
            continue;
        }
        consecutive_failed = 0;

        // The package, ancestors first. An ancestor has strictly fewer
        // ancestors than its descendant, so ordering by ancestor count is a
        // valid block order (Core's `SortForBlock`); the txid breaks ties so
        // the order is deterministic.
        let mut members: Vec<usize> = ancestors[i].iter().copied().filter(|&a| !in_block[a]).collect();
        members.push(i);
        members.sort_by(|&a, &b| {
            ancestors[a].len().cmp(&ancestors[b].len()).then_with(|| entries[a].0.cmp(&entries[b].0))
        });
        for &m in &members {
            in_block[m] = true;
            let p = own(m);
            total_weight += entries[m].1.weight;
            total_sigops = total_sigops.saturating_add(p.sigops);
            selected.push(m);
        }

        // Every descendant of what just went in drops it from its package
        // and is ranked again (Core's `UpdatePackagesForAdded`).
        for &m in &members {
            let p = own(m);
            walk += 1;
            let mut stack: Vec<usize> = children[m].clone();
            while let Some(d) = stack.pop() {
                if visited[d] == walk {
                    continue;
                }
                visited[d] = walk;
                stack.extend_from_slice(&children[d]);
                if in_block[d] {
                    continue;
                }
                let q = &mut package[d];
                q.fee = q.fee.saturating_sub(p.fee);
                q.weight = q.weight.saturating_sub(p.weight);
                q.sigops = q.sigops.saturating_sub(p.sigops);
                version[d] = version[d].wrapping_add(1);
                if minable[d] {
                    heap.push(Ranked {
                        fee: q.fee,
                        weight: q.weight,
                        txid: entries[d].0,
                        idx: d,
                        version: version[d],
                    });
                }
            }
        }
    }

    let mut total_fees = 0u64;
    let mut entries: Vec<Option<(bitcoin::Txid, crate::mempool::pool::MempoolEntry)>> =
        entries.into_iter().map(Some).collect();
    let transactions = selected
        .into_iter()
        .map(|m| {
            let (_, e) = entries[m].take().expect("each candidate is selected once");
            total_fees += e.fee;
            TemplateTx { tx: e.tx, fee: e.fee, weight: e.weight, sigop_cost: e.sigop_cost }
        })
        .collect();
    Selection { transactions, total_weight, total_fees }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;
    use bitcoin::Network;

    #[test]
    fn test_create_empty_template() {
        let dir = std::env::temp_dir().join(format!("satd-template-test-{}", std::process::id()));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(store, flat_files, Network::Regtest, Box::new(NoopVerifier), AssumeValid::Disabled, 450, 4, Default::default(), Default::default(), Default::default()).unwrap();
        let mp = Mempool::new(1_000_000, 0);

        let template = create_template(&cs, &mp);

        assert_eq!(template.height, 1);
        assert_eq!(template.bits.to_consensus(), 0x207fffff);
        assert!(template.transactions.is_empty());
        assert_eq!(template.coinbase_value, 50 * 100_000_000); // 50 BTC subsidy

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `generateblock` supplies its own transaction list, so the mempool
    /// template's fee total describes a block that is not being built.
    /// Claiming it over-claims the coinbase and `connect_block` answers
    /// `bad-cb-amount` — meaning `generateblock` would fail on any node whose
    /// mempool holds a fee-paying transaction. Core builds that template with
    /// `use_mempool = false`, so its coinbase carries the subsidy alone.
    #[test]
    fn an_explicit_tx_list_claims_only_the_subsidy() {
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xB2), coin_at(0))]);
        let tx = tx_spending(confirmed_prev(0xB2), 50_000, 0x42, 0xffff_ffff, 0);
        mp.insert_tx_weighted_for_test(tx, 100, 400, QuarantineScope::acting());

        let subsidy = crate::chain::connect::block_subsidy(cs.network, cs.tip_height() + 1);
        let script = bitcoin::ScriptBuf::new();

        // The mempool has a fee-paying transaction, so the ordinary template
        // claims strictly more than the subsidy.
        let mined = crate::mining::miner::build_block_to_script(&cs, &mp, script.clone(), None)
            .expect("template block");
        let normal_claim: u64 = mined.txdata[0].output.iter().map(|o| o.value.to_sat()).sum();
        assert!(
            normal_claim > subsidy,
            "fixture should have a fee-paying mempool tx: {normal_claim} vs {subsidy}"
        );

        // With an explicit list those fees are not ours to claim.
        let generated =
            crate::mining::miner::build_block_to_script(&cs, &mp, script, Some(Vec::new()))
                .expect("generateblock-style block");
        let claim: u64 = generated.txdata[0].output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(
            claim, subsidy,
            "an explicit transaction list must claim the subsidy alone, not the \
             mempool template's fees"
        );
        assert_eq!(generated.txdata.len(), 1, "only the coinbase was requested");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_coinbase_only_fallback_is_a_valid_template_on_the_named_tip() {
        // When the chain moves during every assembly attempt, `create_template`
        // emits a coinbase-only template rather than one stitched from reads of
        // two different chains. That fallback is only safe if it is itself
        // well-formed and internally consistent -- it names a tip, a height and
        // a subsidy, and carries nothing that could depend on a UTXO set that
        // moved.
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xA1), coin_at(0))]);
        let tx = tx_spending(confirmed_prev(0xA1), 50_000, 0x31, 0xffff_ffff, 0);
        mp.insert_tx_weighted_for_test(tx, 100, 400, QuarantineScope::acting());

        let full = assemble_template(&cs, &mp, true, DEFAULT_BLOCK_MIN_TX_FEE, MAX_BLOCK_WEIGHT);
        let fallback = assemble_template(&cs, &mp, false, DEFAULT_BLOCK_MIN_TX_FEE, MAX_BLOCK_WEIGHT);

        // Without this the comparison below is vacuous: an empty mempool makes
        // both templates transaction-free and the fallback proves nothing.
        assert!(
            !full.transactions.is_empty(),
            "premise: the ordinary template does carry a transaction",
        );
        assert!(
            fallback.transactions.is_empty(),
            "the fallback carries no transactions -- that is what makes it \
             immune to a mixed view",
        );
        assert_eq!(
            fallback.prev_hash, full.prev_hash,
            "it still builds on the tip it names",
        );
        assert_eq!(fallback.height, full.height);
        assert_eq!(fallback.bits, full.bits);
        assert_eq!(
            fallback.coinbase_value,
            crate::chain::connect::block_subsidy(cs.network, fallback.height),
            "no fees, so the coinbase is exactly the subsidy -- a miner that \
             pays itself more than this produces an invalid block",
        );
        assert!(
            full.coinbase_value > fallback.coinbase_value,
            "and the fallback really is the cheaper option it claims to be, \
             which is the whole cost of choosing it",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_template_env() -> (ChainState, Mempool, std::path::PathBuf) {
        make_funded_template_env(&[])
    }

    fn make_funded_template_env(
        coins: &[(bitcoin::OutPoint, crate::storage::coinview::Coin)],
    ) -> (ChainState, Mempool, std::path::PathBuf) {
        make_funded_template_env_with(coins, Box::new(NoopVerifier))
    }

    /// A regtest chain at genesis holding `coins`, verifying scripts with
    /// `verifier`, and an empty mempool.
    pub(crate) fn make_funded_template_env_with(
        coins: &[(bitcoin::OutPoint, crate::storage::coinview::Coin)],
        verifier: Box<dyn crate::validation::script::ScriptVerifier>,
    ) -> (ChainState, Mempool, std::path::PathBuf) {
        use crate::storage::Store as _;
        let dir = std::env::temp_dir().join(format!(
            "satd-template-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let store = Box::new(InMemoryStore::new());
        if !coins.is_empty() {
            let mut batch = crate::storage::StoreBatch::default();
            for (op, c) in coins {
                batch.coin_puts.push((*op, c.clone()));
            }
            store.write_batch(batch).unwrap();
        }
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            verifier,
            AssumeValid::Disabled,
            450,
        4,
        Default::default(),
        Default::default(),
            Default::default(),)
        .unwrap();
        let mp = Mempool::new(1_000_000, 0);
        (cs, mp, dir)
    }

    #[test]
    fn test_template_height_increments() {
        let (cs, mp, dir) = make_template_env();

        let template = create_template(&cs, &mp);
        // At genesis (height 0), the next block should be height 1
        assert_eq!(template.height, cs.tip_height() + 1);
        assert_eq!(template.height, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_witness_commitment_emitted_for_witness_free_template() {
        // Core emits `default_witness_commitment` on every post-segwit
        // template even when nothing carries witness data (#548). The
        // witness root of a witness-free template is the zeroed coinbase
        // slot alone, so the commitment is fixed and non-empty.
        let (cs, mp, _dir) = make_template_env();
        let template = create_template(&cs, &mp);
        assert!(template.transactions.is_empty());
        let hex = compute_witness_commitment_hex(&template.transactions);
        assert!(hex.starts_with("6a24aa21a9ed"), "commitment script header: {hex}");
        assert_eq!(hex.len(), 38 * 2, "OP_RETURN + 36-byte push: {hex}");

        // getblocktemplate carries it (segwit is active from 0 on regtest).
        let gbt = crate::rpc::mining::get_block_template(&cs, &mp).unwrap();
        assert_eq!(gbt["default_witness_commitment"].as_str(), Some(hex.as_str()));
    }

    #[test]
    fn test_template_coinbase_subsidy_only() {
        let (cs, mp, dir) = make_template_env();

        let template = create_template(&cs, &mp);
        let expected_subsidy =
            crate::chain::connect::block_subsidy(Network::Regtest, template.height);
        // With empty mempool, coinbase_value should equal the subsidy alone
        assert_eq!(template.coinbase_value, expected_subsidy);
        assert_eq!(template.coinbase_value, 50 * 100_000_000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_template_bits_regtest() {
        let (cs, mp, dir) = make_template_env();

        let template = create_template(&cs, &mp);
        assert_eq!(template.bits.to_consensus(), 0x207fffff);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_template_prev_hash() {
        let (cs, mp, dir) = make_template_env();

        let tip_hash = cs.tip_hash();
        let template = create_template(&cs, &mp);
        // Template's prev_hash must be the current tip hash
        assert_eq!(template.prev_hash, tip_hash);
        // At genesis, that should be the regtest genesis hash
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert_eq!(template.prev_hash, genesis.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Dependency- and finality-aware selection (#588/#589) ──────────

    pub(crate) fn tx_spending(
        prev: bitcoin::OutPoint,
        out_value: u64,
        out_tag: u8,
        sequence: u32,
        locktime: u32,
    ) -> Transaction {
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[out_tag; 20]);
        Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::from_consensus(locktime),
            input: vec![TxIn {
                previous_output: prev,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(sequence),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
        }
    }

    pub(crate) fn confirmed_prev(tag: u8) -> bitcoin::OutPoint {
        use bitcoin::hashes::Hash;
        bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [tag; 32],
            )),
            vout: 0,
        }
    }

    fn coin_at(height: u32) -> crate::storage::coinview::Coin {
        crate::storage::coinview::Coin {
            amount: 100_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        }
    }

    /// Sigops are a block limit alongside weight: 400 of the 80,000 are
    /// reserved for the coinbase, and a transaction that would bring the total
    /// to 80,000 — not only past it — is left out, as in Core's
    /// `TestChunkBlockLimits`. The higher-fee transaction here would land on
    /// exactly 80,000; the lower-fee one lands one under.
    #[test]
    fn a_template_keeps_to_the_block_sigop_limit() {
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[
            (confirmed_prev(0xB1), coin_at(0)),
            (confirmed_prev(0xB2), coin_at(0)),
        ]);
        let exact = tx_spending(confirmed_prev(0xB1), 50_000, 0x41, 0xffff_ffff, 0);
        let exact = mp.insert_tx_weighted_for_test(exact, 50_000, 400, QuarantineScope::acting());
        mp.set_sigop_cost_for_test(&exact, MAX_BLOCK_SIGOPS_COST - COINBASE_SIGOPS_RESERVE);
        let under = tx_spending(confirmed_prev(0xB2), 50_000, 0x42, 0xffff_ffff, 0);
        let under = mp.insert_tx_weighted_for_test(under, 40_000, 400, QuarantineScope::acting());
        mp.set_sigop_cost_for_test(&under, MAX_BLOCK_SIGOPS_COST - COINBASE_SIGOPS_RESERVE - 1);

        let template = create_template(&cs, &mp);
        let txids: Vec<_> = template.transactions.iter().map(|t| t.tx.compute_txid()).collect();
        assert_eq!(txids, vec![under], "only the transaction that stays under 80,000 fits");
        let total: u64 = template.transactions.iter().map(|t| t.sigop_cost).sum();
        assert!(total + COINBASE_SIGOPS_RESERVE < MAX_BLOCK_SIGOPS_COST);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cpfp_child_is_emitted_after_its_parent() {
        // The child pays a far higher fee rate — that is what CPFP means —
        // so pure fee-rate order put it *before* its parent and the mined
        // block was invalid (#589).
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xA1), coin_at(0))]);

        let parent = tx_spending(confirmed_prev(0xA1), 50_000, 0x31, 0xffff_ffff, 0);
        let parent_txid =
            mp.insert_tx_weighted_for_test(parent, 100, 400, QuarantineScope::acting());
        let child = tx_spending(
            bitcoin::OutPoint { txid: parent_txid, vout: 0 },
            40_000,
            0x32,
            0xffff_ffff,
            0,
        );
        let child_txid =
            mp.insert_tx_weighted_for_test(child, 50_000, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let order: Vec<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        let p = order.iter().position(|t| *t == parent_txid).expect("parent mined");
        let c = order.iter().position(|t| *t == child_txid).expect("child mined");
        assert!(
            p < c,
            "parent must precede the child it funds (order: {order:?})"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_child_whose_parent_is_not_includable_is_dropped() {
        // Parent quarantined `on template`; the child spends it. Including
        // the child alone spends an output that exists nowhere in the
        // block or the chain (#589).
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xA2), coin_at(0))]);

        let parent = tx_spending(confirmed_prev(0xA2), 50_000, 0x33, 0xffff_ffff, 0);
        let parent_txid = mp.insert_tx_weighted_for_test(
            parent,
            100,
            400,
            QuarantineScope { relay: false, template: true },
        );
        let child = tx_spending(
            bitcoin::OutPoint { txid: parent_txid, vout: 0 },
            40_000,
            0x34,
            0xffff_ffff,
            0,
        );
        let child_txid =
            mp.insert_tx_weighted_for_test(child, 50_000, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        assert!(!mined.contains(&parent_txid), "quarantined parent is not mined");
        assert!(
            !mined.contains(&child_txid),
            "child of an unmined mempool parent must be dropped with it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_nonfinal_transaction_is_never_templated() {
        // Admission refuses these since #588, but a reorg can lower the
        // tip after admission and a persisted mempool can predate the
        // check — the template must filter regardless.
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[
            (confirmed_prev(0xA3), coin_at(0)),
            (confirmed_prev(0xA4), coin_at(0)),
        ]);

        let nonfinal = tx_spending(confirmed_prev(0xA3), 50_000, 0x35, 0, 1_000_000);
        let nonfinal_txid =
            mp.insert_tx_weighted_for_test(nonfinal, 50_000, 400, QuarantineScope::acting());
        let fine = tx_spending(confirmed_prev(0xA4), 50_000, 0x36, 0xffff_ffff, 0);
        let fine_txid =
            mp.insert_tx_weighted_for_test(fine, 100, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        assert!(
            !mined.contains(&nonfinal_txid),
            "a non-final transaction would make the mined block invalid"
        );
        assert!(mined.contains(&fine_txid), "the final one is unaffected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_child_of_an_evicted_parent_is_dropped() {
        // The parent was evicted after the child was admitted (expiry,
        // RBF, block-connect conflict): its txid is in neither the
        // mempool nor the UTXO set. "Not in mempool" must not be read as
        // "confirmed" — mining the orphan makes the block invalid with
        // bad-txns-inputs-missingorspent.
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xA6), coin_at(0))]);

        let orphan = tx_spending(confirmed_prev(0xA5), 50_000, 0x37, 0xffff_ffff, 0);
        let orphan_txid =
            mp.insert_tx_weighted_for_test(orphan, 50_000, 400, QuarantineScope::acting());
        let fine = tx_spending(confirmed_prev(0xA6), 50_000, 0x38, 0xffff_ffff, 0);
        let fine_txid = mp.insert_tx_weighted_for_test(fine, 100, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        assert!(
            !mined.contains(&orphan_txid),
            "a spend of a nonexistent coin must never be templated"
        );
        assert!(mined.contains(&fine_txid), "the resolvable one is unaffected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unsatisfied_sequence_lock_is_never_templated() {
        // Both spend a coin confirmed at height 0; the template is for
        // height 1, so one block has elapsed. A 10-block sequence lock is
        // unsatisfied — mining it yields a SequenceLockNotMet block. Like
        // the absolute-finality re-check, admission (#588) normally
        // prevents this, but a reorg-lowered tip or a persisted mempool
        // does not re-run admission.
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[
            (confirmed_prev(0xA7), coin_at(0)),
            (confirmed_prev(0xA8), coin_at(0)),
        ]);

        let locked = tx_spending(confirmed_prev(0xA7), 50_000, 0x39, 10, 0);
        let locked_txid =
            mp.insert_tx_weighted_for_test(locked, 50_000, 400, QuarantineScope::acting());
        let elapsed = tx_spending(confirmed_prev(0xA8), 50_000, 0x3A, 1, 0);
        let elapsed_txid =
            mp.insert_tx_weighted_for_test(elapsed, 100, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        assert!(
            !mined.contains(&locked_txid),
            "an unsatisfied BIP 68 lock would make the mined block invalid"
        );
        assert!(
            mined.contains(&elapsed_txid),
            "a one-block lock on a height-0 coin is satisfied at height 1"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_sequence_lock_counted_from_an_in_template_parent_is_unsatisfiable() {
        // The child's coin would be born in this very block, so zero
        // blocks have elapsed — any nonzero height lock fails. The parent
        // itself is unaffected.
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xA9), coin_at(0))]);

        let parent = tx_spending(confirmed_prev(0xA9), 50_000, 0x3B, 0xffff_ffff, 0);
        let parent_txid =
            mp.insert_tx_weighted_for_test(parent, 100, 400, QuarantineScope::acting());
        let child = tx_spending(
            bitcoin::OutPoint { txid: parent_txid, vout: 0 },
            40_000,
            0x3C,
            1,
            0,
        );
        let child_txid =
            mp.insert_tx_weighted_for_test(child, 50_000, 400, QuarantineScope::acting());

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> = template
            .transactions
            .iter()
            .map(|t| t.tx.compute_txid())
            .collect();
        assert!(mined.contains(&parent_txid), "the parent is mineable");
        assert!(
            !mined.contains(&child_txid),
            "a nonzero lock on a same-block parent can never be satisfied"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // PR 5: a transaction quarantined `on template` is held but never selected
    // into a block this node builds (design §2.4/§3).
    #[test]
    fn test_template_excludes_template_quarantined() {
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_template_env();

        let acting = mp.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        let relay_only =
            mp.insert_scoped_for_test(2, 100, QuarantineScope { relay: true, template: false });
        // High fee rate — if scope were ignored it would sort to the top.
        let template_only =
            mp.insert_scoped_for_test(3, 100_000, QuarantineScope { relay: false, template: true });

        let template = create_template(&cs, &mp);
        let mined: std::collections::HashSet<_> =
            template.transactions.iter().map(|t| t.tx.compute_txid()).collect();

        assert!(mined.contains(&acting), "acting tx is mined");
        assert!(mined.contains(&relay_only), "on-relay tx is still mineable by us");
        assert!(
            !mined.contains(&template_only),
            "on-template tx is excluded even at a far higher fee rate"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A coinbase spend that admission judged mature can stop being mature
    /// under the template's height after a reorg. `connect_block` answers
    /// `bad-txns-premature-spend-of-coinbase` for the *whole block*, so one
    /// such transaction costs the miner every fee in the template.
    #[test]
    fn a_spend_of_an_immature_coinbase_is_not_selected() {
        use crate::mempool::pool::QuarantineScope;
        let immature = crate::storage::coinview::Coin {
            amount: 100_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: true,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xD1), immature)]);
        // The template is built at height 1, so the coinbase has 1 of the 100
        // confirmations it needs.
        let tx = tx_spending(confirmed_prev(0xD1), 50_000, 0x51, 0xffff_ffff, 0);
        let txid = mp.insert_tx_weighted_for_test(tx, 50_000, 400, QuarantineScope::acting());

        let template = create_template_with_floor(&cs, &mp, DEFAULT_BLOCK_MIN_TX_FEE);
        assert!(
            !template.transactions.iter().any(|t| t.tx.compute_txid() == txid),
            "a spend of an immature coinbase reached the template"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The control for the test above: the same coin at the same height,
    /// differing only in the coinbase flag, *is* selected. Without it the
    /// exclusion above would also pass if the fixture never reached selection
    /// at all.
    #[test]
    fn a_spend_of_an_ordinary_output_at_the_same_height_is_selected() {
        use crate::mempool::pool::QuarantineScope;
        let ordinary = crate::storage::coinview::Coin {
            amount: 100_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xD2), ordinary)]);
        let tx = tx_spending(confirmed_prev(0xD2), 50_000, 0x52, 0xffff_ffff, 0);
        let txid = mp.insert_tx_weighted_for_test(tx, 50_000, 400, QuarantineScope::acting());

        let template = create_template_with_floor(&cs, &mp, DEFAULT_BLOCK_MIN_TX_FEE);
        assert!(
            template.transactions.iter().any(|t| t.tx.compute_txid() == txid),
            "an ordinary confirmed spend was not selected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `-blockmintxfee` is a template floor, not a relay floor: a transaction
    /// the mempool accepted is left out when it pays less than the floor.
    #[test]
    fn blockmintxfee_excludes_a_transaction_below_the_floor() {
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[
            (confirmed_prev(0xD3), coin_at(0)),
            (confirmed_prev(0xD4), coin_at(0)),
        ]);
        // 400 weight is 100 vbytes: 500 sats is 5000 sat/kvB, 100 is 1000.
        let below = tx_spending(confirmed_prev(0xD3), 50_000, 0x53, 0xffff_ffff, 0);
        let below_txid = mp.insert_tx_weighted_for_test(below, 100, 400, QuarantineScope::acting());
        let at = tx_spending(confirmed_prev(0xD4), 50_000, 0x54, 0xffff_ffff, 0);
        let at_txid = mp.insert_tx_weighted_for_test(at, 500, 400, QuarantineScope::acting());

        let template = create_template_with_floor(&cs, &mp, 5_000);
        let mined: std::collections::HashSet<_> =
            template.transactions.iter().map(|t| t.tx.compute_txid()).collect();
        assert!(!mined.contains(&below_txid), "a transaction under the floor was mined");
        assert!(mined.contains(&at_txid), "a transaction at the floor was not mined");

        // With the floor off, both are mined — the exclusion above is the
        // floor and not some other selection rule.
        let template = create_template_with_floor(&cs, &mp, 0);
        let mined: std::collections::HashSet<_> =
            template.transactions.iter().map(|t| t.tx.compute_txid()).collect();
        assert!(mined.contains(&below_txid) && mined.contains(&at_txid));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The default floor must not strand what the mempool accepted.
    ///
    /// satd first defaulted `-blockmintxfee` to 1000 sat/kvB — the same value
    /// as the default `-minrelaytxfee` — which is harmless only while the two
    /// agree. Lower the relay floor (which Core's own functional tests do) and
    /// every transaction between the two floors enters the mempool and is
    /// never mined: `generate` stops draining the mempool at all. Core's
    /// default is 1 sat/kvB, three orders of magnitude below the relay floor,
    /// for exactly this reason.
    #[test]
    fn the_default_floor_mines_what_a_low_relay_floor_admitted() {
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xD7), coin_at(0))]);

        // 1000 sats over 10_000 weight (2500 vbytes) is 400 sat/kvB — under
        // satd's default relay floor, and a shape a node running
        // `-minrelaytxfee=0.000001` accepts.
        let tx = tx_spending(confirmed_prev(0xD7), 50_000, 0x57, 0xffff_ffff, 0);
        let txid = mp.insert_tx_weighted_for_test(tx, 1_000, 10_000, QuarantineScope::acting());

        let template = create_template_with_floor(&cs, &mp, DEFAULT_BLOCK_MIN_TX_FEE);
        assert!(
            template.transactions.iter().any(|t| t.tx.compute_txid() == txid),
            "the default template floor stranded a transaction the mempool holds"
        );

        // A zero-fee transaction with nothing paying for it is still skipped,
        // which is what the default floor is *for*.
        let free = tx_spending(confirmed_prev(0xD7), 49_000, 0x58, 0xffff_fffe, 0);
        let free_txid = mp.insert_tx_weighted_for_test(free, 0, 400, QuarantineScope::acting());
        let template = create_template_with_floor(&cs, &mp, DEFAULT_BLOCK_MIN_TX_FEE);
        assert!(
            !template.transactions.iter().any(|t| t.tx.compute_txid() == free_txid),
            "a transaction paying nothing was mined"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Core applies the floor to the *chunk*, so a parent below it rides in on
    /// a child that lifts the package above it. Applying it per-transaction
    /// would drop the parent and strand the paying child — losing both.
    #[test]
    fn blockmintxfee_is_judged_on_the_package_not_the_transaction() {
        use crate::mempool::pool::QuarantineScope;
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xD5), coin_at(0))]);

        // Parent pays nothing; child pays 10_000 sats over 400 weight.
        let parent = tx_spending(confirmed_prev(0xD5), 50_000, 0x55, 0xffff_ffff, 0);
        let parent_txid = parent.compute_txid();
        mp.insert_tx_weighted_for_test(parent, 0, 400, QuarantineScope::acting());
        let child = tx_spending(
            bitcoin::OutPoint { txid: parent_txid, vout: 0 },
            40_000,
            0x56,
            0xffff_ffff,
            0,
        );
        let child_txid =
            mp.insert_tx_weighted_for_test(child, 10_000, 400, QuarantineScope::acting());

        // The package is 10_000 sats over 200 vbytes = 50_000 sat/kvB; the
        // parent alone is 0.
        let template = create_template_with_floor(&cs, &mp, 5_000);
        let mined: std::collections::HashSet<_> =
            template.transactions.iter().map(|t| t.tx.compute_txid()).collect();
        assert!(mined.contains(&parent_txid), "the zero-fee parent was dropped");
        assert!(mined.contains(&child_txid), "the paying child was stranded");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Ancestor-score package selection ────────────────────────────────
    //
    // Mirrors the package cases of Core's `miner_tests` (`src/test/miner_tests.cpp`,
    // `TestPackageSelection`) on satd's assembler. Weights here are chosen so
    // the room below fills to within a few weight units.

    /// Room for transactions: the block less the coinbase reserve, less one.
    /// Core refuses a package that would bring the block *to* its cap (`>=`),
    /// so the heaviest block it assembles is one weight unit under it. These
    /// fixtures filled the full 3,992,000 WU while satd tested `>`; at Core's
    /// boundary that last filler is refused, which would let the cheap child
    /// in `a_low_fee_child_is_not_dragged_in_by_its_parent` take its place.
    const ROOM: usize = MAX_BLOCK_WEIGHT - COINBASE_WEIGHT_RESERVE - 1;

    /// Insert a transaction spending `prev` with the given fee, weight and
    /// sigop cost; returns its txid.
    fn put(mp: &Mempool, prev: bitcoin::OutPoint, tag: u8, fee: u64, weight: usize, sigops: u64) -> bitcoin::Txid {
        use crate::mempool::pool::QuarantineScope;
        let tx = tx_spending(prev, 10_000, tag, 0xffff_ffff, 0);
        let txid = mp.insert_tx_weighted_for_test(tx, fee, weight, QuarantineScope::acting());
        if sigops > 0 {
            mp.set_sigop_cost_for_test(&txid, sigops);
        }
        txid
    }

    fn out0(txid: bitcoin::Txid) -> bitcoin::OutPoint {
        bitcoin::OutPoint { txid, vout: 0 }
    }

    fn mined(template: &BlockTemplate) -> Vec<bitcoin::Txid> {
        template.transactions.iter().map(|t| t.tx.compute_txid()).collect()
    }

    /// Every transaction in the template comes after each of its parents that
    /// is also in the template.
    fn assert_topological(template: &BlockTemplate) {
        let order = mined(template);
        for (i, t) in template.transactions.iter().enumerate() {
            for input in &t.tx.input {
                if let Some(p) = order.iter().position(|x| *x == input.previous_output.txid) {
                    assert!(p < i, "{} precedes its parent {}", order[i], order[p]);
                }
            }
        }
    }

    /// The bug this selection fixes: a high-fee child of a low-fee parent
    /// (CPFP) waited behind the parent's own fee rate, and a block filled by
    /// middling transactions left both out. Ranked by package, the pair
    /// (62.5 sat/WU) beats the fillers (10 sat/WU) and goes in first.
    #[test]
    fn a_cpfp_child_lifts_its_parent_into_a_full_block() {
        let fillers: Vec<_> = (0..4u8).map(|i| (confirmed_prev(0x60 + i), coin_at(0))).collect();
        let mut coins = fillers.clone();
        coins.push((confirmed_prev(0x6F), coin_at(0)));
        let (cs, mp, dir) = make_funded_template_env(&coins);

        let parent = put(&mp, confirmed_prev(0x6F), 0x70, 1, 400, 0);
        let child = put(&mp, out0(parent), 0x71, 50_000, 400, 0);
        for (i, (prev, _)) in fillers.iter().enumerate() {
            put(&mp, *prev, 0x72 + i as u8, 9_980_000, ROOM / 4, 0);
        }

        let template = create_template(&cs, &mp);
        let txs = mined(&template);
        assert!(txs.contains(&parent), "the low-fee parent was left out");
        assert!(txs.contains(&child), "the high-fee child was left out");
        assert_eq!(txs.len(), 5, "the pair and three of the four fillers fit");
        assert_topological(&template);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rank is the package's, not the transaction's own. The child pays
    /// 125 sat/WU itself, but taking it means taking its heavy, nearly free
    /// parent: the pair pays 0.025 sat/WU, below the 10 sat/WU fillers. The
    /// fillers take the block; ranked by its own rate the child would have
    /// brought in half a block of the parent and pushed three fillers out.
    #[test]
    fn a_rich_child_of_a_heavy_cheap_parent_ranks_by_its_package() {
        let fillers: Vec<_> = (0..4u8).map(|i| (confirmed_prev(0x50 + i), coin_at(0))).collect();
        let mut coins = fillers.clone();
        coins.push((confirmed_prev(0x5F), coin_at(0)));
        let (cs, mp, dir) = make_funded_template_env(&coins);

        let parent = put(&mp, confirmed_prev(0x5F), 0x58, 1, ROOM / 2, 0);
        let child = put(&mp, out0(parent), 0x59, 50_000, 400, 0);
        let mut filler_txids = Vec::new();
        for (i, (prev, _)) in fillers.iter().enumerate() {
            filler_txids.push(put(&mp, *prev, 0x5A + i as u8, 9_980_000, ROOM / 4, 0));
        }

        let template = create_template(&cs, &mp);
        let txs = mined(&template);
        assert!(!txs.contains(&parent) && !txs.contains(&child), "the poor package displaced fillers");
        for t in &filler_txids {
            assert!(txs.contains(t), "filler {t} left out");
        }
        assert_eq!(template.coinbase_value - crate::chain::connect::block_subsidy(Network::Regtest, 1), 4 * 9_980_000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ephemeral dust / anchor shape: a parent paying nothing at all, mined
    /// only because its child pays for both. Under the default floor the
    /// package clears `-blockmintxfee`; the parent alone would not.
    #[test]
    fn a_zero_fee_parent_and_its_paying_child_are_both_mined_in_a_full_block() {
        let fillers: Vec<_> = (0..4u8).map(|i| (confirmed_prev(0x80 + i), coin_at(0))).collect();
        let mut coins = fillers.clone();
        coins.push((confirmed_prev(0x8F), coin_at(0)));
        let (cs, mp, dir) = make_funded_template_env(&coins);

        let parent = put(&mp, confirmed_prev(0x8F), 0x90, 0, 400, 0);
        let child = put(&mp, out0(parent), 0x91, 40_000, 400, 0);
        for (i, (prev, _)) in fillers.iter().enumerate() {
            put(&mp, *prev, 0x92 + i as u8, 9_980_000, ROOM / 4, 0);
        }

        let template = create_template_with_floor(&cs, &mp, DEFAULT_BLOCK_MIN_TX_FEE);
        let txs = mined(&template);
        assert!(txs.contains(&parent) && txs.contains(&child), "the anchor pair was left out: {txs:?}");
        assert_topological(&template);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cheap child does not ride on its well-paying parent: once the parent
    /// is in, the child's package is the child alone, ranked on its own fee.
    /// With the block full it loses to the fillers.
    #[test]
    fn a_low_fee_child_is_not_dragged_in_by_its_parent() {
        let fillers: Vec<_> = (0..4u8).map(|i| (confirmed_prev(0xA0 + i), coin_at(0))).collect();
        let mut coins = fillers.clone();
        coins.push((confirmed_prev(0xAF), coin_at(0)));
        let (cs, mp, dir) = make_funded_template_env(&coins);

        let parent = put(&mp, confirmed_prev(0xAF), 0xB0, 40_000, 400, 0);
        let child = put(&mp, out0(parent), 0xB1, 4, 400, 0);
        // Exactly the room the parent leaves.
        for (i, (prev, _)) in fillers.iter().enumerate() {
            put(&mp, *prev, 0xB2 + i as u8, 9_979_000, (ROOM - 400) / 4, 0);
        }

        let txs = mined(&create_template(&cs, &mp));
        assert!(txs.contains(&parent));
        assert!(!txs.contains(&child), "the 0.01 sat/WU child displaced a filler");
        assert_eq!(txs.len(), 5);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After a package goes in, its descendants are ranked on what is left of
    /// theirs (Core's `UpdatePackagesForAdded`). The child ranks 52.5 sat/WU
    /// while its parent is out, but 5 once the parent is in, so the 20 sat/WU
    /// transaction comes before it.
    #[test]
    fn a_descendant_is_reranked_once_its_ancestor_is_in() {
        let (cs, mp, dir) = make_funded_template_env(&[
            (confirmed_prev(0xC0), coin_at(0)),
            (confirmed_prev(0xC1), coin_at(0)),
        ]);
        let parent = put(&mp, confirmed_prev(0xC0), 0xC2, 40_000, 400, 0);
        let child = put(&mp, out0(parent), 0xC3, 2_000, 400, 0);
        let middle = put(&mp, confirmed_prev(0xC1), 0xC4, 8_000, 400, 0);

        let txs = mined(&create_template(&cs, &mp));
        assert_eq!(txs, vec![parent, middle, child]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A package too heavy for what is left is skipped, not the end of
    /// selection: lighter, cheaper transactions still fill the block.
    #[test]
    fn a_package_too_heavy_to_fit_is_skipped_and_lighter_ones_fill() {
        let (cs, mp, dir) = make_funded_template_env(&[
            (confirmed_prev(0xD0), coin_at(0)),
            (confirmed_prev(0xD1), coin_at(0)),
            (confirmed_prev(0xD2), coin_at(0)),
        ]);
        // Each half fits; the package does not.
        let heavy_parent = put(&mp, confirmed_prev(0xD0), 0xD3, 1, ROOM / 2 + 1_000, 0);
        let heavy_child = put(&mp, out0(heavy_parent), 0xD4, 900_000_000, ROOM / 2 + 1_000, 0);
        let light = put(&mp, confirmed_prev(0xD1), 0xD5, 1_000, 400, 0);
        let light2 = put(&mp, confirmed_prev(0xD2), 0xD6, 1_000, 400, 0);

        let txs = mined(&create_template(&cs, &mp));
        assert!(!txs.contains(&heavy_child), "a package over the block weight was mined");
        assert!(txs.contains(&light) && txs.contains(&light2), "selection stopped at the heavy package");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sigops are counted per package: a pair that together crosses 80,000
    /// is refused as a pair even though each half fits. The parent can still
    /// go in on its own; the child then cannot.
    #[test]
    fn a_package_over_the_sigop_limit_is_skipped() {
        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0xE0), coin_at(0))]);
        let parent = put(&mp, confirmed_prev(0xE0), 0xE1, 1_000, 400, 40_000);
        let child = put(&mp, out0(parent), 0xE2, 90_000, 400, 39_700);

        let template = create_template(&cs, &mp);
        let total: u64 = template.transactions.iter().map(|t| t.sigop_cost).sum();
        assert!(total + COINBASE_SIGOPS_RESERVE < MAX_BLOCK_SIGOPS_COST, "template carries {total} sigop cost");
        let txs = mined(&template);
        assert!(txs.contains(&parent));
        assert!(!txs.contains(&child));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Chains and diamonds whose fee rates rise toward the leaves still come
    /// out parents first.
    #[test]
    fn packages_are_emitted_in_topological_order() {
        let (cs, mp, dir) = make_funded_template_env(&[
            (confirmed_prev(0xF0), coin_at(0)),
            (confirmed_prev(0xF1), coin_at(0)),
        ]);
        let a = put(&mp, confirmed_prev(0xF0), 0xF2, 1, 400, 0);
        let b = put(&mp, out0(a), 0xF3, 2, 400, 0);
        let c = put(&mp, out0(b), 0xF4, 90_000, 400, 0);
        // A diamond: e pays two outputs, f and g spend one each, d spends
        // f and g.
        let two_outputs = |prev, tag| {
            let mut tx = tx_spending(prev, 5_000, tag, 0xffff_ffff, 0);
            tx.output.push(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(4_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            });
            tx
        };
        let acting = crate::mempool::pool::QuarantineScope::acting;
        let e = mp.insert_tx_weighted_for_test(two_outputs(confirmed_prev(0xF1), 0xF5), 1, 400, acting());
        let f = put(&mp, out0(e), 0xF6, 1, 400, 0);
        let g = put(&mp, bitcoin::OutPoint { txid: e, vout: 1 }, 0xF8, 1, 400, 0);
        let d_tx = {
            let mut tx = tx_spending(out0(f), 1_000, 0xF7, 0xffff_ffff, 0);
            tx.input.push(bitcoin::TxIn { previous_output: out0(g), ..tx.input[0].clone() });
            tx
        };
        let d = mp.insert_tx_weighted_for_test(d_tx, 80_000, 400, acting());

        let template = create_template(&cs, &mp);
        let txs = mined(&template);
        for t in [a, b, c, d, e, f, g] {
            assert!(txs.contains(&t), "{t} missing");
        }
        assert_topological(&template);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── -blockmaxweight (#836) ───────────────────────────────────────────

    /// `select_transactions` on the mempool's current candidates at the next
    /// height, with the default floor and the given cap: the selection's
    /// `total_weight` is what the cap is judged against.
    fn select_with_cap(cs: &ChainState, mp: &Mempool, block_max_weight: usize) -> Selection {
        let height = cs.tip_height() + 1;
        let mtp = cs.get_median_time_past(height);
        select_transactions(
            cs,
            mp.get_template_entries(),
            height,
            mtp,
            DEFAULT_BLOCK_MIN_TX_FEE,
            block_max_weight,
        )
    }

    /// `-blockmaxweight` caps the template, the coinbase reserve included. It
    /// was parsed and read nowhere, so every template filled to 4,000,000 WU.
    /// Three 60,000 WU transactions fit under 200,000 with the 8,000 reserve
    /// (188,000); a fourth would make 248,000.
    #[test]
    fn a_template_keeps_to_a_configured_block_max_weight() {
        let coins: Vec<_> = (0..4u8).map(|i| (confirmed_prev(0x20 + i), coin_at(0))).collect();
        let (cs, mp, dir) = make_funded_template_env(&coins);
        for (i, (prev, _)) in coins.iter().enumerate() {
            // Distinct fees give a deterministic order; all well above the floor.
            put(&mp, *prev, 0x30 + i as u8, 600_000 - i as u64 * 1_000, 60_000, 0);
        }

        let capped = create_template_with_limits(&cs, &mp, DEFAULT_BLOCK_MIN_TX_FEE, 200_000);
        assert_eq!(capped.transactions.len(), 3, "three fit under the cap, a fourth does not");
        let weight: usize = capped.transactions.iter().map(|t| t.weight).sum();
        assert!(weight + COINBASE_WEIGHT_RESERVE < 200_000, "template weighs {weight} + the reserve");
        assert_eq!(select_with_cap(&cs, &mp, 200_000).total_weight, COINBASE_WEIGHT_RESERVE + 180_000);

        // The same mempool at the default cap takes all four: the three above
        // are the cap's doing, not some other rule's.
        let uncapped = create_template_with_limits(&cs, &mp, DEFAULT_BLOCK_MIN_TX_FEE, MAX_BLOCK_WEIGHT);
        assert_eq!(uncapped.transactions.len(), 4);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A package that would bring the template *to* the cap is refused, as
    /// Core's `TestChunkBlockLimits` refuses on `nBlockWeight + size >=
    /// nBlockMaxWeight`; satd refused only one that went past it. The
    /// higher-fee transaction here lands exactly on the cap, the lower-fee one
    /// a weight unit under it, and the two do not fit together.
    #[test]
    fn the_block_max_weight_boundary_is_exclusive_like_cores() {
        const CAP: usize = 100_000;
        let (cs, mp, dir) = make_funded_template_env(&[
            (confirmed_prev(0x24), coin_at(0)),
            (confirmed_prev(0x25), coin_at(0)),
        ]);
        let exact = put(&mp, confirmed_prev(0x24), 0x34, 920_000, CAP - COINBASE_WEIGHT_RESERVE, 0);
        let under = put(&mp, confirmed_prev(0x25), 0x35, 900_000, CAP - COINBASE_WEIGHT_RESERVE - 1, 0);

        let txs = mined(&create_template_with_limits(&cs, &mp, DEFAULT_BLOCK_MIN_TX_FEE, CAP));
        assert_eq!(txs, vec![under], "only the transaction that stays under the cap fits, not {exact}");
        assert_eq!(select_with_cap(&cs, &mp, CAP).total_weight, CAP - 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cap below the coinbase reserve is raised to it, as Core's
    /// `ClampOptions` raises `nBlockMaxWeight` to `block_reserved_weight`, and
    /// leaves no room for any transaction: the template is coinbase-only. One
    /// above the consensus maximum is lowered to it (the config refuses such a
    /// value before it gets here, with Core's message).
    #[test]
    fn a_block_max_weight_below_the_reserve_yields_a_coinbase_only_template() {
        assert_eq!(clamp_block_max_weight(100), COINBASE_WEIGHT_RESERVE);
        assert_eq!(clamp_block_max_weight(0), COINBASE_WEIGHT_RESERVE);
        assert_eq!(clamp_block_max_weight(200_000), 200_000);
        assert_eq!(clamp_block_max_weight(MAX_BLOCK_WEIGHT + 1), MAX_BLOCK_WEIGHT);

        let (cs, mp, dir) = make_funded_template_env(&[(confirmed_prev(0x26), coin_at(0))]);
        put(&mp, confirmed_prev(0x26), 0x36, 50_000, 400, 0);
        let cap = clamp_block_max_weight(100);
        let template = create_template_with_limits(&cs, &mp, DEFAULT_BLOCK_MIN_TX_FEE, cap);
        assert!(template.transactions.is_empty(), "a 400 WU transaction fit under a 100 WU cap");
        assert_eq!(template.coinbase_value, crate::chain::connect::block_subsidy(Network::Regtest, 1));
        assert_eq!(select_with_cap(&cs, &mp, cap).total_weight, COINBASE_WEIGHT_RESERVE);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Core v30 ends the selection after 1,000 consecutive packages that do
    /// not fit only once the block is within `BLOCK_FULL_ENOUGH_WEIGHT_DELTA`
    /// (4,000 WU) of its cap; v29, which satd copied, did so within the
    /// coinbase reserve (8,000 WU). Here the block stands 6,000 WU short of
    /// its cap after the first transaction, then 1,001 packages too heavy for
    /// the room are followed by a light one that fits. Under v30 selection
    /// carries on and mines it; under v29 it would have given up first.
    #[test]
    fn selection_gives_up_after_1000_failures_at_cores_delta() {
        const CAP: usize = 100_000;
        const HEAVY: u32 = 1_001;
        let outpoint = |tag: u8, vout: u32| bitcoin::OutPoint { txid: confirmed_prev(tag).txid, vout };
        let mut coins = vec![(outpoint(0x27, 0), coin_at(0)), (outpoint(0x28, 0), coin_at(0))];
        coins.extend((0..HEAVY).map(|v| (outpoint(0x29, v), coin_at(0))));
        let (cs, mp, dir) = make_funded_template_env(&coins);

        // 8,000 + 86,000 = 94,000: past v29's `100,000 - 8,000` but not
        // v30's `100,000 - 4,000`.
        let filler = put(&mp, outpoint(0x27, 0), 0x37, 860_000, 86_000, 0);
        // 7,000 WU each, at 5 sat/WU: 94,000 + 7,000 reaches the cap.
        for v in 0..HEAVY {
            put(&mp, outpoint(0x29, v), 0x39, 35_000 + v as u64, 7_000, 0);
        }
        // 400 WU at 2.5 sat/WU: ranked last, and fits.
        let light = put(&mp, outpoint(0x28, 0), 0x38, 1_000, 400, 0);

        let txs = mined(&create_template_with_limits(&cs, &mp, DEFAULT_BLOCK_MIN_TX_FEE, CAP));
        assert_eq!(txs, vec![filler, light], "selection gave up before the package that fits");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
