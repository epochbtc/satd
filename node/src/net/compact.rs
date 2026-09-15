//! BIP 152 compact block relay support.
//!
//! Handles receiving compact blocks, reconstructing full blocks from mempool,
//! and requesting/providing missing transactions.

use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::{Block, BlockHash, Transaction};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::mempool::pool::Mempool;

/// How long a partial reconstruction waits for its `blocktxn` before it is
/// dropped. Bitcoin Core ties the partial block to the peer's in-flight
/// request and lets the block download timeout reap it; satd keeps the
/// partial block in its own table, so it needs its own clock.
pub const COMPACT_PENDING_TIMEOUT: Duration = Duration::from_secs(30);

/// Bitcoin Core's `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK`: at most this many
/// peers may have a partial reconstruction of one block in progress at once.
pub const MAX_CMPCT_INFLIGHT_PER_BLOCK: usize = 3;

/// Bitcoin Core's `MAX_BLOCKTXN_DEPTH`: a `getblocktxn` for a block deeper
/// than this below the tip is answered with the full block instead. It is
/// below `MIN_BLOCKS_TO_KEEP` (288), so a pruned node can always serve it.
pub const MAX_BLOCKTXN_DEPTH: u32 = 10;

/// The most transactions a compact block may claim. Bitcoin Core's bound in
/// `PartiallyDownloadedBlock::InitData`: `MAX_BLOCK_WEIGHT /
/// MIN_SERIALIZABLE_TRANSACTION_WEIGHT`, i.e. 4,000,000 / (4 * 10) — no
/// block can hold more transactions than that, whatever a peer claims.
pub const MAX_COMPACT_BLOCK_TXS: usize = 4_000_000 / (4 * 10);

/// A partially-reconstructed compact block awaiting missing transactions.
///
/// One per peer: the manager keys these by the peer that sent the
/// `cmpctblock`, so the memory they hold is bounded by the peer count rather
/// than by how fast peers can send messages.
pub struct PendingCompact {
    pub hash: BlockHash,
    pub header: bitcoin::block::Header,
    /// Ordered transaction slots: Some = have it, None = need it.
    pub txs: Vec<Option<Transaction>>,
    /// Indices of transactions we requested via GetBlockTxn.
    pub missing_indices: Vec<u64>,
    /// When the entry was created, for [`COMPACT_PENDING_TIMEOUT`].
    pub since: Instant,
    /// We had asked this peer for the block before its `cmpctblock` arrived.
    pub requested: bool,
    /// Reconstruction failed its merkle check and the full block was
    /// requested instead. The entry is kept so that a second `cmpctblock`
    /// for the same block from the same peer is ignored, as Core does.
    pub failed: bool,
    /// The block's height, for the reconstruction log line.
    pub height: u32,
    /// What the mempool pass supplied, completed when the `blocktxn` arrives.
    pub stats: ReconstructStats,
}

impl PendingCompact {
    /// A placeholder for a block whose reconstruction failed and was
    /// re-requested in full from the same peer.
    pub fn failed(hash: BlockHash, header: bitcoin::block::Header, height: u32) -> Self {
        Self {
            hash,
            header,
            txs: Vec::new(),
            missing_indices: Vec::new(),
            since: Instant::now(),
            requested: true,
            failed: true,
            height,
            stats: ReconstructStats::default(),
        }
    }
}

/// A `cmpctblock` that no valid block could produce. Bitcoin Core's
/// `READ_STATUS_INVALID` from `PartiallyDownloadedBlock::InitData`: the peer
/// is misbehaving, whatever the header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeError {
    /// Neither short IDs nor prefilled transactions.
    Empty,
    /// More transactions than [`MAX_COMPACT_BLOCK_TXS`].
    TooManyTxs,
    /// A prefilled transaction with no inputs and no outputs.
    NullPrefilledTx,
    /// A prefilled index past `u16::MAX`, or past the end of the block.
    PrefilledIndexOutOfRange,
}

impl std::fmt::Display for ShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty compact block",
            Self::TooManyTxs => "compact block claims too many transactions",
            Self::NullPrefilledTx => "null prefilled transaction",
            Self::PrefilledIndexOutOfRange => "prefilled transaction index out of range",
        })
    }
}

/// Check the shape Core checks before it touches the mempool
/// (`blockencodings.cpp`, `InitData`). Every failure here is
/// `READ_STATUS_INVALID`.
pub fn check_shape(compact: &HeaderAndShortIds) -> Result<(), ShapeError> {
    if compact.short_ids.is_empty() && compact.prefilled_txs.is_empty() {
        return Err(ShapeError::Empty);
    }
    if compact.short_ids.len() + compact.prefilled_txs.len() > MAX_COMPACT_BLOCK_TXS {
        return Err(ShapeError::TooManyTxs);
    }
    // Indexes are differentially encoded: each is the gap after the previous
    // prefilled slot. Core's arithmetic, including starting at -1.
    let mut last: i64 = -1;
    for (i, prefilled) in compact.prefilled_txs.iter().enumerate() {
        if prefilled.tx.input.is_empty() && prefilled.tx.output.is_empty() {
            return Err(ShapeError::NullPrefilledTx);
        }
        last += i64::from(prefilled.idx) + 1;
        if last > i64::from(u16::MAX) {
            return Err(ShapeError::PrefilledIndexOutOfRange);
        }
        // A slot past every short ID plus every prefilled tx placed so far
        // has neither a transaction nor a short ID.
        if last as usize > compact.short_ids.len() + i {
            return Err(ShapeError::PrefilledIndexOutOfRange);
        }
    }
    Ok(())
}

/// Bitcoin Core's `DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN`.
pub const DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN: usize = 100;

/// A transaction larger than this is not kept in the [`ExtraTxnCache`]. Core
/// bounds each entry by its in-memory size (`RecursiveDynamicUsage < 100000`);
/// satd bounds the serialized size, which is smaller and so keeps no more.
pub const MAX_EXTRA_TXN_BYTES: usize = 100_000;

/// Bitcoin Core's `vExtraTxnForCompact`: a fixed ring of recently seen
/// transactions that are not in the mempool — replaced by RBF, or refused by
/// policy but well-formed — kept so a compact block that includes one still
/// reconstructs locally. Sized by `-blockreconstructionextratxn` (default 100;
/// 0 disables). The oldest entry is overwritten first.
pub struct ExtraTxnCache {
    ring: Vec<Option<(bitcoin::Wtxid, Transaction)>>,
    next: usize,
}

impl ExtraTxnCache {
    pub fn new(capacity: usize) -> Self {
        Self { ring: vec![None; capacity], next: 0 }
    }

    pub fn capacity(&self) -> usize {
        self.ring.len()
    }

    /// Keep `tx`, displacing the oldest entry once the ring is full. A no-op
    /// at capacity 0, and for a transaction over [`MAX_EXTRA_TXN_BYTES`].
    pub fn insert(&mut self, tx: Transaction) {
        if self.ring.is_empty() || tx.total_size() > MAX_EXTRA_TXN_BYTES {
            return;
        }
        let wtxid = tx.compute_wtxid();
        self.ring[self.next] = Some((wtxid, tx));
        self.next = (self.next + 1) % self.ring.len();
    }

    pub fn iter(&self) -> impl Iterator<Item = &(bitcoin::Wtxid, Transaction)> {
        self.ring.iter().flatten()
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Where the transactions of a reconstruction came from, counted while the
/// block was being filled — never by checking the mempool again afterwards,
/// when a transaction may have come or gone. Field names follow Bitcoin Core
/// #35724's reconstruction log line so the two can be compared.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconstructStats {
    pub prefilled: u64,
    pub prefilled_bytes: u64,
    pub mempool: u64,
    pub mempool_bytes: u64,
    /// Filled from the [`ExtraTxnCache`], not the mempool.
    pub extra: u64,
    pub extra_bytes: u64,
    /// Requested with `getblocktxn`.
    pub requested: u64,
    pub requested_bytes: u64,
    /// Prefilled transactions we already had, in the mempool or the extra
    /// cache: bytes the sender need not have spent.
    pub redundant_prefilled: u64,
}

/// The result of matching a well-formed compact block against the mempool.
pub enum Reconstruction {
    /// Every slot was filled; the block still has to pass its merkle check.
    Complete(Block, ReconstructStats),
    /// Some slots must be requested with `getblocktxn`.
    Partial {
        txs: Vec<Option<Transaction>>,
        missing_indices: Vec<u64>,
        stats: ReconstructStats,
    },
}

/// Where a candidate for a slot came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Mempool,
    Extra,
}

type Candidates = HashMap<ShortId, Option<(bitcoin::Wtxid, Transaction, Source)>>;

/// Offer `tx` as the transaction behind `short_id`. The first offer fills
/// the entry; the same transaction offered again (it can be in both the
/// mempool and the extra cache) changes nothing; a *different* transaction
/// on a short ID already claimed makes it ambiguous (`None`), and the slot
/// will be requested rather than guessed. Core's `InitData` does the same.
fn offer(
    matched: &mut Candidates,
    short_id: ShortId,
    wtxid: bitcoin::Wtxid,
    tx: &Transaction,
    source: Source,
) {
    match matched.get_mut(&short_id) {
        None => {
            matched.insert(short_id, Some((wtxid, tx.clone(), source)));
        }
        Some(Some((have, _, _))) if *have == wtxid => {}
        Some(slot) => *slot = None,
    }
}

/// Attempt to reconstruct a full block from a compact block using the mempool
/// and the extra-transaction cache.
///
/// Returns [`ShapeError`] for a message no valid block could produce; call
/// [`check_shape`] first if the distinction matters before the mempool pass.
pub fn try_reconstruct(
    compact: &HeaderAndShortIds,
    mempool: &Mempool,
    extra: &ExtraTxnCache,
) -> Result<Reconstruction, ShapeError> {
    check_shape(compact)?;
    let siphash_keys = ShortId::calculate_siphash_keys(&compact.header, compact.nonce);

    // Short IDs that the peer announced more than once. Two block slots sharing
    // one short ID must never both be filled from the same mempool tx (that
    // duplicates a transaction and mutates the block); request every such slot
    // via `getblocktxn` so the peer supplies the real, distinct transactions.
    // Core hard-fails reconstruction on this collision and re-requests; routing
    // the individual slots is the same outcome with less bandwidth.
    let mut short_id_counts: HashMap<ShortId, u32> = HashMap::with_capacity(compact.short_ids.len());
    for short_id in &compact.short_ids {
        *short_id_counts.entry(*short_id).or_insert(0) += 1;
    }
    let prefilled_wtxids: std::collections::HashSet<bitcoin::Wtxid> =
        compact.prefilled_txs.iter().map(|p| p.tx.compute_wtxid()).collect();
    let mut stats = ReconstructStats::default();
    // Prefilled transactions we already held. A set, because a transaction
    // can be in the mempool and the extra cache at once.
    let mut redundant: std::collections::HashSet<bitcoin::Wtxid> = std::collections::HashSet::new();

    // Match the mempool against the announced short IDs: short_id -> the one
    // mempool tx carrying it, or `None` when more than one does.
    //
    // This is the one assist-adjacent consumer that deliberately reads the
    // FULL union, NOT a scope-filtered view: a peer's compact block may
    // contain transactions our policy quarantines, and a quarantined tx we
    // already hold lets us reconstruct the block locally instead of paying a
    // `getblocktxn` round trip (design §2.4). Filtering by scope here would
    // silently reintroduce those round trips. Validating / reconstructing
    // someone else's block is consensus-only and never consults policy (I1
    // corollary, design §3) — so do NOT filter here.
    //
    // A short ID is only 6 bytes, so two distinct mempool transactions can
    // hash to the same short ID (crafted, or ~1-in-2^48 by chance). Using
    // either one to fill a slot would be a guess: if it is the wrong tx the
    // reconstructed block fails its merkle check. So a short ID that matches
    // more than one mempool tx is marked ambiguous (`None`) and treated as
    // unavailable — the slot is requested instead. This mirrors Bitcoin Core's
    // `PartiallyDownloadedBlock::InitData`, which resets a slot when a second
    // mempool tx collides on its short ID.
    //
    // The mempool is walked under its read lock without copying it: only a
    // transaction whose short ID the peer actually announced is cloned.
    let mut by_short_id: Candidates = mempool.with_entries(|entries| {
        let mut matched = Candidates::new();
        for entry in entries.values() {
            let wtxid = entry.tx.compute_wtxid();
            if prefilled_wtxids.contains(&wtxid) {
                redundant.insert(wtxid);
            }
            let short_id = ShortId::with_siphash_keys(&wtxid.to_raw_hash(), siphash_keys);
            if short_id_counts.contains_key(&short_id) {
                offer(&mut matched, short_id, wtxid, &entry.tx, Source::Mempool);
            }
        }
        matched
    });

    // Then the extra-transaction cache, under the same collision rule.
    for (wtxid, tx) in extra.iter() {
        if prefilled_wtxids.contains(wtxid) {
            redundant.insert(*wtxid);
        }
        let short_id = ShortId::with_siphash_keys(&wtxid.to_raw_hash(), siphash_keys);
        if short_id_counts.contains_key(&short_id) {
            offer(&mut by_short_id, short_id, *wtxid, tx, Source::Extra);
        }
    }

    stats.redundant_prefilled = redundant.len() as u64;

    // Total number of transactions in the block
    let total_txs = compact.prefilled_txs.len() + compact.short_ids.len();
    let mut txs: Vec<Option<Transaction>> = vec![None; total_txs];

    // Place prefilled transactions (differentially encoded indices). The
    // shape check has already proved every index lands inside the block.
    let mut idx = 0usize;
    for prefilled in &compact.prefilled_txs {
        idx += prefilled.idx as usize;
        stats.prefilled += 1;
        stats.prefilled_bytes += prefilled.tx.total_size() as u64;
        txs[idx] = Some(prefilled.tx.clone());
        idx += 1;
    }

    // Fill in remaining slots from mempool using short IDs
    let mut short_id_iter = compact.short_ids.iter();
    let mut missing_indices = Vec::new();
    for (i, slot) in txs.iter_mut().enumerate() {
        if slot.is_some() {
            continue; // Already prefilled
        }
        if let Some(short_id) = short_id_iter.next() {
            // A short ID the peer announced twice, or one matching two mempool
            // txs, is not safe to fill locally — request it so we get the real
            // transaction for this slot instead of duplicating one.
            let ambiguous = short_id_counts.get(short_id).is_some_and(|&n| n > 1);
            match by_short_id.get(short_id) {
                Some(Some((_, tx, source))) if !ambiguous => {
                    let bytes = tx.total_size() as u64;
                    match source {
                        Source::Mempool => {
                            stats.mempool += 1;
                            stats.mempool_bytes += bytes;
                        }
                        Source::Extra => {
                            stats.extra += 1;
                            stats.extra_bytes += bytes;
                        }
                    }
                    *slot = Some(tx.clone());
                }
                _ => missing_indices.push(i as u64),
            }
        }
    }

    if missing_indices.is_empty() {
        // All transactions found — reconstruct the block
        let txdata: Vec<Transaction> = txs.into_iter().map(|t| t.unwrap()).collect();
        Ok(Reconstruction::Complete(
            Block {
                header: compact.header,
                txdata,
            },
            stats,
        ))
    } else {
        Ok(Reconstruction::Partial {
            txs,
            missing_indices,
            stats,
        })
    }
}

/// Why a `blocktxn` did not complete a pending reconstruction. The split is
/// Bitcoin Core's `READ_STATUS_INVALID` versus `READ_STATUS_FAILED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteError {
    /// The reply does not answer the request: wrong transaction count, or
    /// the entry has nothing outstanding. The peer is misbehaving.
    Invalid,
    /// The filled block fails its merkle or witness commitment check. A
    /// short-ID collision produces this on an honest relay, so the right
    /// response is to fetch the full block, not to penalise the peer.
    Mutated,
}

/// Complete a pending compact block with the missing transactions from a
/// `blocktxn` response, then apply the mutation check Core runs at the end of
/// `FillBlock`.
pub fn complete_pending(
    pending: PendingCompact,
    block_txns: &BlockTransactions,
    segwit_active: bool,
) -> Result<(Block, ReconstructStats), CompleteError> {
    let mut stats = pending.stats;
    if pending.failed || pending.missing_indices.is_empty() {
        return Err(CompleteError::Invalid);
    }
    let mut txs = pending.txs;

    if block_txns.transactions.len() != pending.missing_indices.len() {
        return Err(CompleteError::Invalid);
    }

    for (tx, &idx) in block_txns.transactions.iter().zip(pending.missing_indices.iter()) {
        let i = idx as usize;
        if i >= txs.len() {
            return Err(CompleteError::Invalid);
        }
        txs[i] = Some(tx.clone());
        stats.requested += 1;
        stats.requested_bytes += tx.total_size() as u64;
    }

    // Check all slots are filled
    if txs.iter().any(|t| t.is_none()) {
        return Err(CompleteError::Invalid);
    }

    let txdata: Vec<Transaction> = txs.into_iter().map(|t| t.unwrap()).collect();
    let block = Block {
        header: pending.header,
        txdata,
    };
    if crate::validation::block::is_block_mutated(&block, segwit_active) {
        return Err(CompleteError::Mutated);
    }
    Ok((block, stats))
}

/// Create a GetBlockTxn request for missing transactions.
pub fn make_get_block_txn(block_hash: BlockHash, missing_indices: &[u64]) -> BlockTransactionsRequest {
    BlockTransactionsRequest {
        block_hash,
        indexes: missing_indices.to_vec(),
    }
}

/// Bitcoin Core's `MAX_CMPCTBLOCK_DEPTH`: a `MSG_CMPCT_BLOCK` getdata for a
/// block deeper than this below the tip is answered with the full block.
pub const MAX_CMPCTBLOCK_DEPTH: u32 = 5;

/// Build the `cmpctblock` form of `block` — version 2 (witness), a fresh
/// random nonce, the coinbase prefilled — for sending. BIP 152: "Nodes SHOULD
/// NOT use the same nonce across multiple different blocks."
pub fn make_compact_block(block: &Block) -> Result<HeaderAndShortIds, bitcoin::bip152::Error> {
    let nonce: u64 = rand::random();
    HeaderAndShortIds::from_block(block, nonce, 2, &[])
}

/// `-cmpctblockprefillbytes` default: the transaction bytes, beyond the
/// coinbase, a prefilled `cmpctblock` may carry. Under the median TCP
/// congestion window measured for Core #35558 (14 480 bytes), so the larger
/// message still leaves in one flight.
pub const DEFAULT_CMPCTBLOCK_PREFILL_BYTES: usize = 8192;

/// The transactions of a block worth prefilling: the ones this node did not
/// have when the block arrived, so its peers most likely lack them too (Core
/// #35558). Indexes into `block.txdata`, in block order, never the coinbase.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PrefillCandidates {
    /// In neither the mempool nor the extra-transaction cache.
    pub needed: Vec<usize>,
    /// Not in the mempool, but in the extra-transaction cache: a replaced or
    /// policy-refused transaction a peer is less likely to be missing than
    /// one nobody relayed to us at all.
    pub extra: Vec<usize>,
}

/// Classify `block`'s transactions against the mempool and the extra cache.
///
/// Call it before the block is connected: connecting removes its
/// transactions from the mempool, after which every one looks missing.
/// `None` when the mempool is write-locked -- the caller is about to announce
/// the block, and a prefill is not worth delaying the announcement for.
pub fn prefill_candidates(block: &Block, mempool: &Mempool, extra: &ExtraTxnCache) -> Option<PrefillCandidates> {
    let absent: Vec<usize> = mempool.try_with_entries(|entries| {
        block
            .txdata
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, tx)| entries.get(&tx.compute_txid()).is_none_or(|e| e.tx != **tx))
            .map(|(i, _)| i)
            .collect()
    })?;
    let cached: std::collections::HashSet<bitcoin::Wtxid> = extra.iter().map(|(w, _)| *w).collect();
    let (extra, needed) = absent
        .into_iter()
        .partition(|&i| cached.contains(&block.txdata[i].compute_wtxid()));
    Some(PrefillCandidates { needed, extra })
}

/// Which candidates to prefill within `budget` transaction bytes (witness
/// serialization; the coinbase, always prefilled, is not counted). Needed
/// transactions first, then extra-cache ones, so a tight budget still carries
/// the transactions nobody relayed; each group in block order, greedily, so
/// one that does not fit is skipped and a smaller later one still goes.
/// Returns sorted indexes for [`HeaderAndShortIds::from_block`].
pub fn prefill_indexes(block: &Block, candidates: &PrefillCandidates, budget: usize) -> Vec<usize> {
    let mut used = 0usize;
    let mut chosen: Vec<usize> = Vec::new();
    for &i in candidates.needed.iter().chain(&candidates.extra) {
        let Some(tx) = block.txdata.get(i) else { continue };
        if i == 0 || chosen.contains(&i) {
            continue;
        }
        let size = tx.total_size();
        if used + size <= budget {
            used += size;
            chosen.push(i);
        }
    }
    chosen.sort_unstable();
    chosen
}

/// [`make_compact_block`] with `prefill` (sorted, no coinbase) prefilled as
/// well, under a caller-chosen nonce.
pub fn make_prefilled_compact_block(
    block: &Block,
    nonce: u64,
    prefill: &[usize],
) -> Result<HeaderAndShortIds, bitcoin::bip152::Error> {
    HeaderAndShortIds::from_block(block, nonce, 2, prefill)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip152::BlockTransactions;
    use bitcoin::constants::genesis_block;
    use bitcoin::Network;

    fn regtest_genesis() -> Block {
        genesis_block(Network::Regtest)
    }

    /// Helper: create a simple coinbase-like transaction for testing.
    fn make_test_tx(value: u64) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(value),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    fn pending_for(
        header: bitcoin::block::Header,
        txs: Vec<Option<Transaction>>,
        missing_indices: Vec<u64>,
    ) -> PendingCompact {
        PendingCompact {
            hash: header.block_hash(),
            header,
            txs,
            missing_indices,
            since: Instant::now(),
            requested: false,
            failed: false,
            height: 1,
            stats: ReconstructStats::default(),
        }
    }

    #[test]
    fn test_make_compact_block() {
        let block = regtest_genesis();
        let compact = make_compact_block(&block);
        assert!(compact.is_ok());
        let compact = compact.unwrap();
        // The compact block's header should match the original
        assert_eq!(compact.header, block.header);
    }

    #[test]
    fn test_make_compact_preserves_header() {
        let block = regtest_genesis();
        let compact = make_compact_block(&block).unwrap();
        assert_eq!(compact.header.prev_blockhash, block.header.prev_blockhash);
        assert_eq!(compact.header.merkle_root, block.header.merkle_root);
        assert_eq!(compact.header.time, block.header.time);
        assert_eq!(compact.header.bits, block.header.bits);
        assert_eq!(compact.header.nonce, block.header.nonce);
        assert_eq!(compact.header.version, block.header.version);
    }

    #[test]
    fn test_make_get_block_txn() {
        let hash = regtest_genesis().block_hash();
        let indices = vec![1, 3, 5];
        let req = make_get_block_txn(hash, &indices);
        assert_eq!(req.block_hash, hash);
        assert_eq!(req.indexes, vec![1, 3, 5]);
    }

    #[test]
    fn test_complete_pending_wrong_count() {
        let header = regtest_genesis().header;
        let tx = make_test_tx(5000);
        let pending = pending_for(header, vec![Some(tx.clone()), None, None], vec![1, 2]);
        // Provide only 1 transaction but 2 are missing
        let block_txns = BlockTransactions {
            block_hash: header.block_hash(),
            transactions: vec![make_test_tx(100)],
        };
        assert_eq!(
            complete_pending(pending, &block_txns, false).unwrap_err(),
            CompleteError::Invalid
        );
    }

    #[test]
    fn test_complete_pending_success() {
        let tx0 = make_test_tx(5000);
        let tx1 = make_test_tx(1000);
        let tx2 = make_test_tx(2000);
        let mut header = regtest_genesis().header;
        header.merkle_root = Block {
            header,
            txdata: vec![tx0.clone(), tx1.clone(), tx2.clone()],
        }
        .compute_merkle_root()
        .unwrap();

        let pending = pending_for(header, vec![Some(tx0.clone()), None, None], vec![1, 2]);
        let block_txns = BlockTransactions {
            block_hash: header.block_hash(),
            transactions: vec![tx1.clone(), tx2.clone()],
        };
        let (block, stats) = complete_pending(pending, &block_txns, false)
            .unwrap_or_else(|e| panic!("expected a completed block, got {e:?}"));
        assert_eq!(stats.requested, 2, "the two blocktxn transactions are counted as requested");
        assert_eq!(block.header, header);
        assert_eq!(block.txdata.len(), 3);
        assert_eq!(block.txdata[0], tx0);
        assert_eq!(block.txdata[1], tx1);
        assert_eq!(block.txdata[2], tx2);
    }

    #[test]
    fn test_complete_pending_index_out_of_bounds() {
        let header = regtest_genesis().header;
        let tx0 = make_test_tx(5000);

        // Index 5 is out of bounds (only 1 slot)
        let pending = pending_for(header, vec![Some(tx0)], vec![5]);
        let block_txns = BlockTransactions {
            block_hash: header.block_hash(),
            transactions: vec![make_test_tx(100)],
        };
        assert_eq!(
            complete_pending(pending, &block_txns, false).unwrap_err(),
            CompleteError::Invalid
        );
    }

    #[test]
    fn test_reconstruct_coinbase_only_block() {
        // The regtest genesis block has only a coinbase transaction.
        // When we make a compact block from it, the coinbase is prefilled.
        // Reconstruction with an empty mempool should succeed since all
        // transactions are prefilled.
        let block = regtest_genesis();
        let compact = make_compact_block(&block).unwrap();

        let mempool = Mempool::new(300_000_000, 1_000);
        match try_reconstruct(&compact, &mempool, &ExtraTxnCache::new(0)) {
            Ok(Reconstruction::Complete(reconstructed, _)) => {
                assert_eq!(reconstructed.header, block.header);
                assert_eq!(reconstructed.txdata.len(), block.txdata.len());
            }
            _ => panic!("expected successful reconstruction of coinbase-only block"),
        }
    }

    #[test]
    fn test_reconstruct_empty_mempool_missing_txs() {
        // Create a block with coinbase + extra transaction.
        // The compact block will prefill the coinbase but the extra tx
        // needs to come from the mempool. With an empty mempool, we get
        // Err(PendingCompact) with the missing index.
        let mut block = regtest_genesis();
        let extra_tx = make_test_tx(1234);
        block.txdata.push(extra_tx);

        let compact = make_compact_block(&block).unwrap();
        let mempool = Mempool::new(300_000_000, 1_000);
        match try_reconstruct(&compact, &mempool, &ExtraTxnCache::new(0)) {
            Ok(Reconstruction::Partial { missing_indices, .. }) => {
                assert_eq!(missing_indices, vec![1]);
            }
            _ => panic!("expected a partial reconstruction with missing transactions"),
        }
    }

    // PR 5: compact-block reconstruction is the one assist-adjacent consumer
    // that reads the FULL union — a tx our policy fully quarantines must still
    // reconstruct the peer's block locally, sparing a `getblocktxn` round trip
    // (design §2.4). Reconstructing someone else's block is consensus-only.
    #[test]
    fn reconstruct_uses_quarantined_txs() {
        use crate::mempool::pool::QuarantineScope;
        let full_quarantine = QuarantineScope { relay: true, template: true };

        let mut block = regtest_genesis();
        let extra_tx = make_test_tx(4321);
        block.txdata.push(extra_tx.clone());
        let compact = make_compact_block(&block).unwrap();

        let mempool = Mempool::new(300_000_000, 1_000);
        // The extra tx is present but fully quarantined (assisted on neither
        // relay nor template).
        mempool.insert_tx_scoped_for_test(extra_tx, full_quarantine);

        match try_reconstruct(&compact, &mempool, &ExtraTxnCache::new(0)) {
            Ok(Reconstruction::Complete(reconstructed, _)) => {
                assert_eq!(reconstructed.header, block.header);
                assert_eq!(reconstructed.txdata.len(), block.txdata.len());
            }
            _ => panic!("quarantined tx must still be available for reconstruction"),
        }
    }

    /// A peer that announces the same short ID for two different block slots
    /// must not cause the same mempool transaction to be placed in both slots
    /// (a duplicated tx mutates the block, fails its merkle check, and gets the
    /// honest relayer banned with no re-request). Both colliding slots must be
    /// routed to `getblocktxn` instead. Mirrors Bitcoin Core's
    /// `PartiallyDownloadedBlock::InitData` collision handling.
    #[test]
    fn reconstruct_requests_a_duplicated_short_id_instead_of_duplicating_a_tx() {
        use bitcoin::bip152::PrefilledTransaction;

        let header = regtest_genesis().header;
        let nonce: u64 = 0x0123_4567_89ab_cdef;
        let keys = ShortId::calculate_siphash_keys(&header, nonce);

        // One mempool tx; compute the short ID the peer would announce for it.
        let mempool_tx = make_test_tx(4321);
        let sid =
            ShortId::with_siphash_keys(&mempool_tx.compute_wtxid().to_raw_hash(), keys);

        // Coinbase prefilled at index 0, then the SAME short ID announced twice
        // (slots 1 and 2). A valid block never repeats a transaction, so two
        // slots sharing a short ID are two distinct txs colliding — neither may
        // be filled from the single mempool match.
        let coinbase = make_test_tx(5000);
        let compact = HeaderAndShortIds {
            header,
            nonce,
            prefilled_txs: vec![PrefilledTransaction { idx: 0, tx: coinbase.clone() }],
            short_ids: vec![sid, sid],
        };

        let mempool = Mempool::new(300_000_000, 1_000);
        mempool.insert_tx_scoped_for_test(
            mempool_tx,
            crate::mempool::pool::QuarantineScope::acting(),
        );

        match try_reconstruct(&compact, &mempool, &ExtraTxnCache::new(0)) {
            Ok(Reconstruction::Partial { txs, missing_indices, .. }) => {
                assert_eq!(
                    missing_indices,
                    vec![1, 2],
                    "both colliding slots must be requested via getblocktxn"
                );
                assert_eq!(txs[0].as_ref(), Some(&coinbase));
                assert!(txs[1].is_none());
                assert!(txs[2].is_none());
            }
            Ok(Reconstruction::Complete(block, _)) => panic!(
                "must not reconstruct a block with a duplicated tx (txdata len {})",
                block.txdata.len()
            ),
            Err(e) => panic!("well-formed compact block reported as {e}"),
        }
    }

    fn compact_with(
        short_ids: usize,
        prefilled: Vec<(u16, Transaction)>,
    ) -> HeaderAndShortIds {
        use bitcoin::bip152::PrefilledTransaction;
        HeaderAndShortIds {
            header: regtest_genesis().header,
            nonce: 7,
            short_ids: (0..short_ids)
                .map(|i| ShortId::from([i as u8, (i >> 8) as u8, (i >> 16) as u8, 1, 2, 3]))
                .collect(),
            prefilled_txs: prefilled
                .into_iter()
                .map(|(idx, tx)| PrefilledTransaction { idx, tx })
                .collect(),
        }
    }

    /// Every shape Core's `InitData` calls `READ_STATUS_INVALID` is reported as
    /// such before the mempool is consulted, and none of them yields a
    /// reconstruction the manager could park as pending state.
    #[test]
    fn malformed_cmpctblock_shapes_are_invalid_not_pending() {
        let null_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let cases: Vec<(&str, HeaderAndShortIds, ShapeError)> = vec![
            ("empty", compact_with(0, vec![]), ShapeError::Empty),
            (
                "too many transactions",
                compact_with(MAX_COMPACT_BLOCK_TXS, vec![(0, make_test_tx(1))]),
                ShapeError::TooManyTxs,
            ),
            (
                "null prefilled tx",
                compact_with(2, vec![(0, null_tx)]),
                ShapeError::NullPrefilledTx,
            ),
            (
                "prefilled index past the end",
                // Two slots in total (one short ID + one prefilled): index 2
                // is outside the block.
                compact_with(1, vec![(2, make_test_tx(1))]),
                ShapeError::PrefilledIndexOutOfRange,
            ),
            (
                "second prefilled index past the end",
                compact_with(1, vec![(0, make_test_tx(1)), (2, make_test_tx(2))]),
                ShapeError::PrefilledIndexOutOfRange,
            ),
            (
                "differential index overflowing u16",
                compact_with(
                    70_000,
                    vec![(u16::MAX, make_test_tx(1)), (u16::MAX, make_test_tx(2))],
                ),
                ShapeError::PrefilledIndexOutOfRange,
            ),
        ];
        let mempool = Mempool::new(300_000_000, 1_000);
        for (name, compact, want) in cases {
            assert_eq!(check_shape(&compact), Err(want), "{name}");
            assert!(
                matches!(try_reconstruct(&compact, &mempool, &ExtraTxnCache::new(0)), Err(e) if e == want),
                "{name}: try_reconstruct must refuse the shape"
            );
        }

        // The boundaries themselves are well-formed.
        assert_eq!(check_shape(&compact_with(1, vec![(1, make_test_tx(1))])), Ok(()));
        assert_eq!(
            check_shape(&compact_with(MAX_COMPACT_BLOCK_TXS - 1, vec![(0, make_test_tx(1))])),
            Ok(())
        );
    }

    /// The core of the bound Core's constant encodes, restated so a typo in
    /// the derivation cannot slip through: 4,000,000 weight units, at least
    /// 40 per serializable transaction.
    #[test]
    fn max_compact_block_txs_is_cores_bound() {
        assert_eq!(MAX_COMPACT_BLOCK_TXS, 100_000);
    }

    /// A `blocktxn` that fills every slot but produces a block whose merkle
    /// root does not match the header is a possible short-ID collision, not
    /// misbehaviour: Core's `FillBlock` returns `READ_STATUS_FAILED` and the
    /// caller fetches the full block without penalising the peer.
    #[test]
    fn completed_block_failing_merkle_is_mutated_not_invalid() {
        let header = regtest_genesis().header; // merkle root commits to genesis only
        let pending = pending_for(header, vec![Some(make_test_tx(5000)), None], vec![1]);
        let block_txns = BlockTransactions {
            block_hash: header.block_hash(),
            transactions: vec![make_test_tx(1)],
        };
        assert_eq!(
            complete_pending(pending, &block_txns, false).unwrap_err(),
            CompleteError::Mutated
        );
    }

    /// A pending entry kept only to remember a failed reconstruction has
    /// nothing outstanding; a `blocktxn` against it is not an answer.
    #[test]
    fn blocktxn_against_a_failed_entry_is_invalid() {
        let header = regtest_genesis().header;
        let pending = PendingCompact::failed(header.block_hash(), header, 1);
        let block_txns = BlockTransactions {
            block_hash: header.block_hash(),
            transactions: vec![],
        };
        assert_eq!(
            complete_pending(pending, &block_txns, false).unwrap_err(),
            CompleteError::Invalid
        );
    }

    /// Reconstruction runs on every `cmpctblock` a peer sends, so it must not
    /// copy the mempool to build its short-ID table. `Mempool::get_all_entries`
    /// clones every entry; the reconstruction path walks the pool under its
    /// read lock with `with_entries` and clones only the transactions a short
    /// ID matched. Not observable through the API, so pinned on the source.
    #[test]
    fn reconstruct_reads_the_mempool_without_cloning_it() {
        let src = include_str!("compact.rs");
        let body = &src[..src.find("#[cfg(test)]").expect("test module")];
        let fn_start = body.find("pub fn try_reconstruct(").expect("try_reconstruct");
        let fn_body = &body[fn_start..];
        let fn_body = &fn_body[..fn_body.find("\n}\n").expect("end of try_reconstruct")];
        assert!(
            !fn_body.contains("get_all_entries"),
            "try_reconstruct must not clone the mempool"
        );
        assert!(
            fn_body.contains("mempool.with_entries("),
            "try_reconstruct must read the mempool under its lock"
        );
    }

    /// Only an announced short ID pulls a transaction out of the mempool:
    /// unrelated entries are neither cloned into the result nor able to
    /// disturb the match for the one that is announced.
    #[test]
    fn reconstruct_takes_only_announced_transactions_from_a_large_mempool() {
        let mut block = regtest_genesis();
        let wanted = make_test_tx(777_777);
        block.txdata.push(wanted.clone());
        let compact = make_compact_block(&block).unwrap();

        let mempool = Mempool::new(300_000_000, 1_000);
        for v in 0..500u64 {
            mempool.insert_tx_scoped_for_test(
                make_test_tx(10_000 + v),
                crate::mempool::pool::QuarantineScope::acting(),
            );
        }
        mempool.insert_tx_scoped_for_test(
            wanted.clone(),
            crate::mempool::pool::QuarantineScope::acting(),
        );
        match try_reconstruct(&compact, &mempool, &ExtraTxnCache::new(0)) {
            Ok(Reconstruction::Complete(b, _)) => assert_eq!(b.txdata[1], wanted),
            _ => panic!("the announced tx must be found among unrelated entries"),
        }
    }

    // ---- extra-transaction cache ----

    #[test]
    fn extra_txn_cache_wraps_at_capacity_overwriting_the_oldest() {
        let mut cache = ExtraTxnCache::new(3);
        for v in 1..=4u64 {
            cache.insert(make_test_tx(v));
        }
        let kept: Vec<u64> = cache.iter().map(|(_, tx)| tx.output[0].value.to_sat()).collect();
        assert_eq!(cache.len(), 3);
        assert!(!kept.contains(&1), "the oldest entry is overwritten: {kept:?}");
        for v in 2..=4 {
            assert!(kept.contains(&v), "{v} is kept: {kept:?}");
        }
    }

    #[test]
    fn extra_txn_cache_of_zero_keeps_nothing() {
        let mut cache = ExtraTxnCache::new(0);
        cache.insert(make_test_tx(1));
        assert!(cache.is_empty());
    }

    #[test]
    fn extra_txn_cache_refuses_an_oversized_transaction() {
        let mut big = make_test_tx(1);
        big.output[0].script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x6a; MAX_EXTRA_TXN_BYTES]);
        let mut cache = ExtraTxnCache::new(4);
        cache.insert(big);
        assert!(cache.is_empty());
    }

    /// A transaction that left the mempool (replaced) but sits in the extra
    /// cache still fills its slot, and is counted as `extra`, not `mempool`.
    #[test]
    fn a_replaced_tx_in_the_extra_cache_is_found_by_the_next_reconstruction() {
        let mut block = regtest_genesis();
        let replaced = make_test_tx(31_337);
        let in_pool = make_test_tx(42);
        block.txdata.push(replaced.clone());
        block.txdata.push(in_pool.clone());
        let compact = make_compact_block(&block).unwrap();

        let mempool = Mempool::new(300_000_000, 1_000);
        mempool.insert_tx_scoped_for_test(in_pool, crate::mempool::pool::QuarantineScope::acting());
        let mut extra = ExtraTxnCache::new(10);
        extra.insert(replaced.clone());

        match try_reconstruct(&compact, &mempool, &extra) {
            Ok(Reconstruction::Complete(b, stats)) => {
                assert_eq!(b.txdata[1], replaced);
                assert_eq!((stats.prefilled, stats.mempool, stats.extra), (1, 1, 1), "{stats:?}");
                assert_eq!(stats.extra_bytes, replaced.total_size() as u64);
            }
            _ => panic!("the cached tx must fill its slot"),
        }
        // Without the cache the same block needs a round trip.
        match try_reconstruct(&compact, &mempool, &ExtraTxnCache::new(0)) {
            Ok(Reconstruction::Partial { missing_indices, .. }) => assert_eq!(missing_indices, vec![1]),
            _ => panic!("without the cache the slot must be requested"),
        }
    }

    /// Two different transactions on one short ID — one in the mempool, one
    /// in the extra cache — make the slot ambiguous: it is requested, never
    /// guessed. The same transaction offered from both places is one match.
    /// A 48-bit collision cannot be ground in a test, so the matcher is fed
    /// the colliding short ID directly.
    #[test]
    fn a_short_id_matching_mempool_and_extra_cache_is_ambiguous() {
        let sid = ShortId::from([1, 2, 3, 4, 5, 6]);
        let a = make_test_tx(1_001);
        let b = make_test_tx(1_002);

        let mut same = Candidates::new();
        offer(&mut same, sid, a.compute_wtxid(), &a, Source::Mempool);
        offer(&mut same, sid, a.compute_wtxid(), &a, Source::Extra);
        assert!(
            matches!(same.get(&sid), Some(Some((_, tx, Source::Mempool))) if *tx == a),
            "the same transaction from both sources is one match"
        );

        let mut collision = Candidates::new();
        offer(&mut collision, sid, a.compute_wtxid(), &a, Source::Mempool);
        offer(&mut collision, sid, b.compute_wtxid(), &b, Source::Extra);
        assert!(matches!(collision.get(&sid), Some(None)), "a mempool/cache collision is ambiguous");

        let mut two_cached = Candidates::new();
        offer(&mut two_cached, sid, a.compute_wtxid(), &a, Source::Extra);
        offer(&mut two_cached, sid, b.compute_wtxid(), &b, Source::Extra);
        assert!(matches!(two_cached.get(&sid), Some(None)), "two cached txs on one short ID are ambiguous");
    }

    /// A test transaction whose serialization is about `bytes` long.
    fn sized_tx(value: u64, bytes: usize) -> Transaction {
        let mut tx = make_test_tx(value);
        tx.output[0].script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x6a; bytes.saturating_sub(60)]);
        tx
    }

    fn block_of(txs: Vec<Transaction>) -> Block {
        let mut block = regtest_genesis();
        block.txdata.extend(txs);
        block
    }

    #[test]
    fn prefill_packs_needed_before_extra_each_in_block_order() {
        let block = block_of((1..=4).map(|v| sized_tx(v, 200)).collect());
        let candidates = PrefillCandidates { needed: vec![2, 4], extra: vec![1] };
        // Room for two: both needed ones, not the extra-cache one before them.
        let budget = block.txdata[2].total_size() + block.txdata[4].total_size();
        assert_eq!(prefill_indexes(&block, &candidates, budget), vec![2, 4]);
        // Room for all three, returned sorted for `from_block`.
        assert_eq!(prefill_indexes(&block, &candidates, 10_000), vec![1, 2, 4]);
    }

    #[test]
    fn prefill_respects_its_budget_and_keeps_a_later_small_candidate() {
        let block = block_of(vec![sized_tx(1, 300), sized_tx(2, 5_000), sized_tx(3, 300)]);
        let candidates = PrefillCandidates { needed: vec![1, 2, 3], extra: vec![] };
        let budget = 1_000;
        let chosen = prefill_indexes(&block, &candidates, budget);
        assert_eq!(chosen, vec![1, 3], "the oversize middle one is skipped, the small last one kept");
        let used: usize = chosen.iter().map(|&i| block.txdata[i].total_size()).sum();
        assert!(used <= budget);
        assert!(prefill_indexes(&block, &candidates, 0).is_empty(), "a zero budget prefills nothing beyond the coinbase");
    }

    #[test]
    fn prefill_never_names_the_coinbase_or_an_index_past_the_block() {
        let block = block_of(vec![sized_tx(1, 100)]);
        let candidates = PrefillCandidates { needed: vec![0, 1, 7], extra: vec![1] };
        assert_eq!(prefill_indexes(&block, &candidates, 10_000), vec![1]);
    }

    #[test]
    fn a_block_whose_transactions_were_all_in_the_mempool_prefills_the_coinbase_only() {
        let a = make_test_tx(111);
        let b = make_test_tx(222);
        let block = block_of(vec![a.clone(), b.clone()]);
        let mempool = Mempool::new(300_000_000, 1_000);
        for tx in [a, b] {
            mempool.insert_tx_scoped_for_test(tx, crate::mempool::pool::QuarantineScope::acting());
        }
        let candidates = prefill_candidates(&block, &mempool, &ExtraTxnCache::new(10)).unwrap();
        assert_eq!(candidates, PrefillCandidates::default());
        let prefill = prefill_indexes(&block, &candidates, DEFAULT_CMPCTBLOCK_PREFILL_BYTES);
        let compact = make_prefilled_compact_block(&block, 1, &prefill).unwrap();
        assert_eq!(compact.prefilled_txs.len(), 1, "coinbase only");
    }

    #[test]
    fn prefill_candidates_split_missing_transactions_by_the_extra_cache() {
        let in_pool = make_test_tx(1);
        let replaced = make_test_tx(2);
        let unseen = make_test_tx(3);
        let block = block_of(vec![in_pool.clone(), replaced.clone(), unseen]);
        let mempool = Mempool::new(300_000_000, 1_000);
        mempool.insert_tx_scoped_for_test(in_pool, crate::mempool::pool::QuarantineScope::acting());
        let mut extra = ExtraTxnCache::new(10);
        extra.insert(replaced);
        let candidates = prefill_candidates(&block, &mempool, &extra).unwrap();
        assert_eq!(candidates, PrefillCandidates { needed: vec![3], extra: vec![2] });
    }

    #[test]
    fn a_prefilled_compact_block_shares_the_plain_ones_short_ids_and_reconstructs() {
        let unseen = make_test_tx(9);
        let block = block_of(vec![make_test_tx(8), unseen.clone()]);
        let plain = make_prefilled_compact_block(&block, 42, &[]).unwrap();
        let prefilled = make_prefilled_compact_block(&block, 42, &[2]).unwrap();
        assert_eq!(prefilled.short_ids, plain.short_ids[..1], "same nonce, same IDs for what is not prefilled");
        let mempool = Mempool::new(300_000_000, 1_000);
        mempool.insert_tx_scoped_for_test(block.txdata[1].clone(), crate::mempool::pool::QuarantineScope::acting());
        match try_reconstruct(&prefilled, &mempool, &ExtraTxnCache::new(0)) {
            Ok(Reconstruction::Complete(b, stats)) => {
                assert_eq!(b.txdata[2], unseen);
                assert_eq!(stats.requested, 0);
                assert_eq!(stats.prefilled, 2);
            }
            _ => panic!("a block prefilled with what the receiver lacks needs no round trip"),
        }
    }

    #[test]
    fn prefill_candidates_skip_rather_than_wait_on_a_write_locked_mempool() {
        let src = include_str!("compact.rs");
        let body = &src[..src.find("#[cfg(test)]").expect("test module")];
        let start = body.find("pub fn prefill_candidates(").expect("prefill_candidates");
        let f = &body[start..];
        let f = &f[..f.find("\n}\n").expect("end of prefill_candidates")];
        assert!(f.contains("mempool.try_with_entries("), "must not block the announcement on the mempool lock");
    }
}
