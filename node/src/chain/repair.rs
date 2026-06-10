//! Surgical repair for a single lost connect delta.
//!
//! The WAL-less BulkLoad data-loss bug (see the `flush_durable`
//! all-column-families fix) could evaporate one block's entire connect
//! batch while leaving every neighboring block — and the tip pointer —
//! intact: the block's created coins are missing, the coins it spent
//! linger as phantoms, and its txindex / undo / address-index /
//! `outpoint_spend` / cumulative-tx-count rows are absent. The node
//! then wedges with `bad-txns-inputs-missingorspent` the first time a
//! later block spends one of the missing coins.
//!
//! Such a hole is repairable in place, without a reindex, because the
//! lost delta commutes with everything connected after it:
//!
//! - No later block can have spent the hole's missing outputs — those
//!   blocks connected successfully *without* them.
//! - No later block can have re-spent the hole's inputs — the active
//!   chain contains no double spends, so the phantoms are untouched.
//! - Txids are unique (BIP 34), so no later block re-created the same
//!   outpoints.
//!
//! The current chainstate is therefore exactly `correct(tip) − Δ(hole)`,
//! and re-applying the hole's connect delta yields exactly
//! `correct(tip)`. This module rebuilds that delta with the *real*
//! [`connect_block`] (full validation, including scripts — the phantom
//! prevouts are all still present), verifies the damage matches the
//! lost-delta signature before writing anything, and refuses to run
//! against any state it does not understand.
//!
//! It also rewrites the cumulative-tx-count rows of every descendant up
//! to the tip: when those blocks connected over the hole,
//! `get_cumulative_tx_count(parent)` returned `None` and the counts
//! restarted from zero.

use std::collections::HashSet;

use bitcoin::{Block, BlockHash, Network, OutPoint, Txid};

use crate::chain::connect::{self, ConnectError, ConnectParams};
use crate::index::address::AddressIndexConfig;
use crate::storage::blockindex::BlockStatus;
use crate::storage::flatfile::FlatFilePos;
use crate::storage::{Store, StoreError};
use crate::validation::script::ScriptVerifier;

#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("block {0} not found in the block index")]
    MissingIndexEntry(BlockHash),
    #[error(
        "damage does not match the lost-connect-delta signature, refusing to touch the \
         chainstate: {0}"
    )]
    SignatureMismatch(String),
    #[error("re-connect of the lost block failed: {0}")]
    Connect(#[from] ConnectError),
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
    #[error("postcondition failed after writing the repair batch: {0}")]
    Postcondition(String),
}

/// What the repair found and (when `applied`) wrote.
#[derive(Debug)]
pub struct RepairReport {
    pub block_hash: BlockHash,
    pub height: u32,
    pub tip_hash: BlockHash,
    pub tip_height: u32,
    /// Coins the lost delta creates — net: block outputs minus
    /// unspendables and minus outputs spent within the block itself,
    /// i.e. exactly what reaches the store (matching CoinCache's
    /// elision on the live path).
    pub coins_created: usize,
    /// Phantom coins the lost delta removes — net: the block's spent
    /// inputs minus intra-block spends.
    pub coins_spent: usize,
    pub tx_index_rows: usize,
    pub addr_funding_rows: usize,
    pub addr_spending_rows: usize,
    pub outpoint_spend_rows: usize,
    /// Descendant blocks whose cumulative-tx-count rows were wrong
    /// (computed over the hole) and got rewritten.
    pub chain_tx_rewrites: usize,
    /// False for a dry run: the batch was built and verified but not
    /// written.
    pub applied: bool,
}

/// Verify that `block`'s connect delta is wholesale missing from
/// `store`, rebuild it with the real connect path, and (when `apply`)
/// write it atomically and durably — without moving the tip, which
/// stays at the descendant the node already reached.
///
/// `block` must be the full block read from flat files (the caller owns
/// flat-file access); its index entry and parent must already be in the
/// store. Every precondition failure aborts before any write.
pub fn repair_lost_connect_delta(
    store: &dyn Store,
    block: &Block,
    script_verifier: &dyn ScriptVerifier,
    network: Network,
    num_threads: usize,
    address_index: &AddressIndexConfig,
    apply: bool,
) -> Result<RepairReport, RepairError> {
    let block_hash = block.block_hash();
    let entry = store
        .get_block_index(&block_hash)
        .ok_or(RepairError::MissingIndexEntry(block_hash))?;
    let height = entry.height;

    if matches!(entry.status, BlockStatus::HeaderOnly | BlockStatus::Pruned) {
        return Err(RepairError::SignatureMismatch(format!(
            "block index entry has status {:?} — no local block data to re-connect",
            entry.status
        )));
    }

    let parent = store.get_block_index(&block.header.prev_blockhash).ok_or_else(|| {
        RepairError::SignatureMismatch(format!(
            "parent {} missing from the block index",
            block.header.prev_blockhash
        ))
    })?;
    if parent.height + 1 != height {
        return Err(RepairError::SignatureMismatch(format!(
            "parent height {} does not precede block height {}",
            parent.height, height
        )));
    }

    // The hole sits strictly below the tip: descendants connected over
    // it. Walk the header chain down from the tip (never the
    // height→hash index, which has a hole of its own here) — this both
    // proves the block is on the active chain and collects the
    // descendants whose cumulative-tx-count rows need rewriting.
    let tip_hash = store
        .get_tip()
        .ok_or_else(|| RepairError::SignatureMismatch("store has no tip".into()))?;
    let tip_entry = store
        .get_block_index(&tip_hash)
        .ok_or_else(|| RepairError::SignatureMismatch("tip has no block index entry".into()))?;
    let tip_height = tip_entry.height;
    if tip_height <= height {
        return Err(RepairError::SignatureMismatch(format!(
            "block height {} is not below the tip ({}) — a lost delta always has \
             connected descendants above it",
            height, tip_height
        )));
    }
    // (hash, num_tx) of each descendant, tip-first.
    let mut descendants: Vec<(BlockHash, u32)> = Vec::with_capacity((tip_height - height) as usize);
    let mut cursor_hash = tip_hash;
    let mut cursor = tip_entry;
    while cursor.height > height {
        descendants.push((cursor_hash, cursor.num_tx));
        cursor_hash = cursor.header.prev_blockhash;
        cursor = store.get_block_index(&cursor_hash).ok_or_else(|| {
            RepairError::SignatureMismatch(format!(
                "header chain from the tip is broken at {cursor_hash}"
            ))
        })?;
    }
    if cursor_hash != block_hash {
        return Err(RepairError::SignatureMismatch(format!(
            "active chain has {} at height {}, not this block",
            cursor_hash, height
        )));
    }
    descendants.reverse(); // ascending height, block's child first

    // The height→hash row was part of the lost batch; tolerate it
    // already being correct, but never overwrite a different hash.
    if let Some(indexed) = store.get_block_hash_by_height(height)
        && indexed != block_hash
    {
        return Err(RepairError::SignatureMismatch(format!(
            "height index maps {} to {} — refusing to overwrite",
            height, indexed
        )));
    }

    // Lost-delta signature, every piece: undo and txindex rows absent,
    // created outputs absent, spent inputs still present as phantoms.
    if store.get_undo(&block_hash).is_some() {
        return Err(RepairError::SignatureMismatch(
            "undo data already present — this block's delta does not look lost".into(),
        ));
    }
    let block_txids: HashSet<Txid> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();
    for tx in &block.txdata {
        let txid = tx.compute_txid();
        if let Some(loc) = store.get_tx_location(&txid) {
            return Err(RepairError::SignatureMismatch(format!(
                "txindex already maps {txid} to {loc}"
            )));
        }
        for vout in 0..tx.output.len() as u32 {
            let outpoint = OutPoint { txid, vout };
            if store.get_coin(&outpoint).is_some() {
                return Err(RepairError::SignatureMismatch(format!(
                    "created output {outpoint} is already in the UTXO set"
                )));
            }
        }
        if tx.is_coinbase() {
            continue;
        }
        for input in &tx.input {
            let prevout = input.previous_output;
            if block_txids.contains(&prevout.txid) {
                continue; // intra-block spend; never reached the store
            }
            if store.get_coin(&prevout).is_none() {
                return Err(RepairError::SignatureMismatch(format!(
                    "spent input {prevout} is missing — the damage is wider than one \
                     block's lost delta"
                )));
            }
        }
    }
    // The parent's count anchors the rebuilt chain_tx series; connect
    // would silently restart from zero without it.
    let parent_chain_tx =
        store.get_cumulative_tx_count(&block.header.prev_blockhash).ok_or_else(|| {
            RepairError::SignatureMismatch(format!(
                "parent {} has no cumulative tx count",
                block.header.prev_blockhash
            ))
        })?;

    // MTP over the 11 blocks ending at the parent, via header-chain
    // walk (the height index cannot be trusted around the hole).
    let mut timestamps = Vec::with_capacity(11);
    let mut mtp_cursor = parent.clone();
    loop {
        timestamps.push(mtp_cursor.header.time);
        if timestamps.len() == 11 || mtp_cursor.height == 0 {
            break;
        }
        mtp_cursor = store.get_block_index(&mtp_cursor.header.prev_blockhash).ok_or_else(|| {
            RepairError::SignatureMismatch(format!(
                "header chain is broken at {} while computing MTP",
                mtp_cursor.header.prev_blockhash
            ))
        })?;
    }
    timestamps.sort_unstable();
    let median_time_past = timestamps[timestamps.len() / 2];

    // Rebuild the delta with the production connect path — full
    // validation, scripts included: every prevout is still present.
    let flat_pos = FlatFilePos { file_number: entry.file_number, data_pos: entry.data_pos };
    let mut batch = connect::connect_block(&ConnectParams {
        store,
        block,
        height,
        parent_chainwork: &parent.chainwork,
        flat_pos,
        script_verifier,
        median_time_past,
        network,
        pre_verified_txs: None,
        num_threads,
        precomputed_txids: None,
        address_index,
        #[cfg(feature = "block-filter-index")]
        filter_index: &Default::default(),
        phase_tracker: None,
    })?;

    // connect_block stamps the batch as the new tip; the node's real
    // tip is many blocks above this one and must not move.
    debug_assert_eq!(batch.tip, Some(block_hash));
    batch.tip = None;

    // Net out intra-block spends. connect_block emits gross coin
    // traffic — an output created and spent within the same block
    // appears in BOTH coin_puts and coin_removes. On the live write
    // path CoinCache cancels those pairs before they reach the store
    // (FRESH elision); this tool writes to the store directly. Stores
    // now guarantee the StoreBatch remove-wins contract (puts applied
    // before removes — RocksDbStore historically did the opposite,
    // which would have RESURRECTED 2,382 spent coins on the first
    // production repair), but we still net the pairs here: it keeps
    // the report's counts net (comparable with the connect-time store
    // log), skips pointless writes, and keeps the coin counters exact.
    // Drop the pairs from the coins CF only — undo, txindex,
    // address-index, and outpoint-spend rows legitimately record
    // intra-block events and pass through untouched, exactly as they
    // do via CoinCache in production.
    let intra_block_pairs: HashSet<OutPoint> = {
        let removed: HashSet<OutPoint> =
            batch.coin_removes.iter().map(|(op, _, _)| *op).collect();
        batch.coin_puts.iter().map(|(op, _)| *op).filter(|op| removed.contains(op)).collect()
    };
    batch.coin_puts.retain(|(op, _)| !intra_block_pairs.contains(op));
    batch.coin_removes.retain(|(op, _, _)| !intra_block_pairs.contains(op));

    // Descendants connected over the hole computed their cumulative tx
    // counts from a missing parent (`unwrap_or(0)`); rewrite every row
    // that disagrees with the repaired series.
    let mut chain_tx = parent_chain_tx + block.txdata.len() as u64;
    let mut chain_tx_rewrites = 0usize;
    for (hash, num_tx) in &descendants {
        chain_tx += u64::from(*num_tx);
        if store.get_cumulative_tx_count(hash) != Some(chain_tx) {
            batch.chain_tx_puts.push((*hash, chain_tx));
            chain_tx_rewrites += 1;
        }
    }

    // Capture verification keys before the batch is consumed.
    let created: Vec<OutPoint> = batch.coin_puts.iter().map(|(op, _)| *op).collect();
    let spent: Vec<OutPoint> = batch.coin_removes.iter().map(|(op, _, _)| *op).collect();
    let tx_rows: Vec<Txid> = batch.tx_index_puts.iter().map(|(txid, _)| *txid).collect();
    let report = RepairReport {
        block_hash,
        height,
        tip_hash,
        tip_height,
        coins_created: created.len(),
        coins_spent: spent.len(),
        tx_index_rows: tx_rows.len(),
        addr_funding_rows: batch.addr_funding_puts.len(),
        addr_spending_rows: batch.addr_spending_puts.len(),
        outpoint_spend_rows: batch.outpoint_spend_puts.len(),
        chain_tx_rewrites,
        applied: apply,
    };

    if !apply {
        return Ok(report);
    }

    // Normal-mode write (WAL-backed) followed by a durable flush: the
    // repair must survive a crash immediately after the tool exits.
    store.write_batch(batch)?;
    store.flush_durable()?;

    // Postconditions: the delta is in place and nothing else moved.
    let created_set: HashSet<OutPoint> = created.iter().copied().collect();
    for outpoint in &created {
        if store.get_coin(outpoint).is_none() {
            return Err(RepairError::Postcondition(format!(
                "created coin {outpoint} missing after write"
            )));
        }
    }
    for outpoint in &spent {
        if !created_set.contains(outpoint) && store.get_coin(outpoint).is_some() {
            return Err(RepairError::Postcondition(format!(
                "phantom coin {outpoint} still present after write"
            )));
        }
    }
    for txid in &tx_rows {
        if store.get_tx_location(txid) != Some(block_hash) {
            return Err(RepairError::Postcondition(format!(
                "txindex row for {txid} missing after write"
            )));
        }
    }
    if store.get_undo(&block_hash).is_none() {
        return Err(RepairError::Postcondition("undo data missing after write".into()));
    }
    if store.get_block_hash_by_height(height) != Some(block_hash) {
        return Err(RepairError::Postcondition("height index row missing after write".into()));
    }
    if store.get_tip() != Some(tip_hash) {
        return Err(RepairError::Postcondition("tip moved — it must stay at the descendant".into()));
    }
    if store.get_cumulative_tx_count(&block_hash)
        != Some(parent_chain_tx + block.txdata.len() as u64)
    {
        return Err(RepairError::Postcondition(
            "cumulative tx count for the repaired block is wrong after write".into(),
        ));
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::connect::block_subsidy;
    use crate::storage::StoreBatch;
    use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
    use crate::storage::coinview::Coin;
    use crate::storage::db::InMemoryStore;
    use crate::validation::script::NoopVerifier;
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Block, Sequence, Transaction, TxIn, TxOut, Witness};

    fn make_coinbase(height: u32, extra_outputs: usize) -> Transaction {
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();
        let mut output = vec![TxOut {
            value: Amount::from_sat(block_subsidy(height)),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }];
        for _ in 0..extra_outputs {
            output.push(TxOut { value: Amount::ZERO, script_pubkey: bitcoin::ScriptBuf::new() });
        }
        Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output,
        }
    }

    fn seal(prev_blockhash: BlockHash, txdata: Vec<Transaction>) -> Block {
        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    fn index_entry(block: &Block, height: u32, status: BlockStatus) -> BlockIndexEntry {
        BlockIndexEntry {
            header: block.header,
            height,
            status,
            num_tx: block.txdata.len() as u32,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        }
    }

    /// Damage any store the canonical way: genesis connected, a seeded
    /// coin, block 1 — coinbase + a spend of the seeded coin + a
    /// **chained intra-block spend** of that spend's output — whose
    /// connect delta was LOST (only its DataStored index entry
    /// survives), and block 2 connected on top of the hole. Returns
    /// (block1, block2_hash, seeded_outpoint).
    fn populate_holed_store(store: &dyn Store) -> (Block, BlockHash, OutPoint) {
        // Genesis, fully connected and counted.
        let genesis = seal(BlockHash::all_zeros(), vec![make_coinbase(0, 0)]);
        let genesis_hash = genesis.block_hash();
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((genesis_hash, index_entry(&genesis, 0, BlockStatus::Valid)));
        batch.height_hash_puts.push((0, genesis_hash));
        batch.tip = Some(genesis_hash);
        batch.chain_tx_puts.push((genesis_hash, 1));
        store.write_batch(batch).unwrap();

        // A spendable non-coinbase coin for block 1 to consume.
        let seeded = OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x42; 32])),
            vout: 0,
        };
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((
            seeded,
            Coin {
                amount: 50_000_000,
                script_pubkey: bitcoin::ScriptBuf::new(),
                height: 0,
                coinbase: false,
            },
        ));
        store.write_batch(batch).unwrap();

        // Block 1 spends the seeded coin. Its connect delta is "lost":
        // only the DataStored index entry (the pre-connect accept-time
        // write) goes in.
        let spend = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: seeded,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        // Chained intra-block spend: consumes `spend`'s output within
        // the same block, so the rebuilt batch carries that outpoint as
        // a put+remove PAIR — the case the netting logic must cancel
        // before writing to a raw store.
        let chained = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: spend.compute_txid(), vout: 0 },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let block1 = seal(genesis_hash, vec![make_coinbase(1, 0), spend, chained]);
        let block1_hash = block1.block_hash();
        let mut batch = StoreBatch::default();
        batch
            .block_index_puts
            .push((block1_hash, index_entry(&block1, 1, BlockStatus::DataStored)));
        store.write_batch(batch).unwrap();

        // Block 2 connects over the hole, exactly as production did:
        // its chain_tx anchors on a missing parent count (→ 0).
        let block2 = seal(block1_hash, vec![make_coinbase(2, 0)]);
        let block2_hash = block2.block_hash();
        let batch2 = connect::connect_block(&ConnectParams {
            store,
            block: &block2,
            height: 2,
            parent_chainwork: &[0u8; 32],
            flat_pos: FlatFilePos { file_number: 0, data_pos: 0 },
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
            address_index: &AddressIndexConfig::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
        })
        .unwrap();
        store.write_batch(batch2).unwrap();
        assert_eq!(store.get_tip(), Some(block2_hash));
        // The production wrongness this sets up: block 2's count
        // restarted from zero over the hole.
        assert_eq!(store.get_cumulative_tx_count(&block2_hash), Some(1));

        (block1, block2_hash, seeded)
    }

    fn make_holed_store() -> (InMemoryStore, Block, BlockHash, OutPoint) {
        let store = InMemoryStore::new();
        let (block1, block2_hash, seeded) = populate_holed_store(&store);
        (store, block1, block2_hash, seeded)
    }

    #[test]
    fn repairs_a_lost_delta_without_moving_the_tip() {
        let (store, block1, block2_hash, seeded) = make_holed_store();
        let block1_hash = block1.block_hash();

        // Dry run first: reports the delta, writes nothing.
        let report = repair_lost_connect_delta(
            &store,
            &block1,
            &NoopVerifier,
            Network::Regtest,
            1,
            &AddressIndexConfig::default(),
            false,
        )
        .unwrap();
        assert!(!report.applied);
        assert_eq!(report.height, 1);
        // Net of the intra-block pair: only the seeded coin is spent
        // cross-block, and only the coinbase + chained outputs survive.
        assert_eq!(report.coins_spent, 1);
        assert_eq!(report.coins_created, 2);
        assert_eq!(report.tx_index_rows, 3);
        // The address index keeps the gross intra-block events.
        assert_eq!(report.chain_tx_rewrites, 1, "block 2's zero-anchored count must be rewritten");
        assert!(store.get_coin(&seeded).is_some(), "dry run must not touch the store");
        assert!(store.get_undo(&block1_hash).is_none(), "dry run must not touch the store");

        // Apply.
        let report = repair_lost_connect_delta(
            &store,
            &block1,
            &NoopVerifier,
            Network::Regtest,
            1,
            &AddressIndexConfig::default(),
            true,
        )
        .unwrap();
        assert!(report.applied);

        // The phantom is gone, the block's surviving outputs exist, the
        // intra-block-spent output does NOT, every index row is back,
        // and the tip never moved.
        assert!(store.get_coin(&seeded).is_none());
        let intra = OutPoint { txid: block1.txdata[1].compute_txid(), vout: 0 };
        assert!(
            store.get_coin(&intra).is_none(),
            "intra-block-spent output must not be resurrected"
        );
        assert!(
            store.get_coin(&OutPoint { txid: block1.txdata[2].compute_txid(), vout: 0 }).is_some()
        );
        for tx in &block1.txdata {
            assert_eq!(store.get_tx_location(&tx.compute_txid()), Some(block1_hash));
        }
        assert!(store.get_undo(&block1_hash).is_some());
        assert_eq!(store.get_block_hash_by_height(1), Some(block1_hash));
        assert_eq!(store.get_tip(), Some(block2_hash));
        // chain_tx series rebuilt: genesis 1, block1 1+3=4, block2 4+1=5.
        assert_eq!(store.get_cumulative_tx_count(&block1_hash), Some(4));
        assert_eq!(store.get_cumulative_tx_count(&block2_hash), Some(5));
    }

    /// The same end-to-end repair against a REAL RocksDB store. This is
    /// the test that caught the resurrection bug the InMemoryStore
    /// can't: `RocksDbStore::write_batch` used to apply coin_removes
    /// before coin_puts inside one WriteBatch (last write per key
    /// wins), so an un-netted intra-block put+remove pair left the
    /// spent coin alive in the UTXO set. The store now applies puts
    /// first (remove wins) AND the repair nets pairs — this test guards
    /// the composition end-to-end.
    #[test]
    fn repair_on_rocksdb_does_not_resurrect_intra_block_spends() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            crate::storage::rocksdb_store::RocksDbStore::open(dir.path(), true, 16, false, -1)
                .unwrap();
        let (block1, block2_hash, seeded) = populate_holed_store(&store);
        let block1_hash = block1.block_hash();

        let report = repair_lost_connect_delta(
            &store,
            &block1,
            &NoopVerifier,
            Network::Regtest,
            1,
            &AddressIndexConfig::default(),
            true,
        )
        .unwrap();
        assert!(report.applied);
        assert_eq!(report.coins_created, 2);
        assert_eq!(report.coins_spent, 1);

        let intra = OutPoint { txid: block1.txdata[1].compute_txid(), vout: 0 };
        assert!(
            store.get_coin(&intra).is_none(),
            "intra-block-spent output must not be resurrected in RocksDB"
        );
        assert!(
            store.get_coin(&OutPoint { txid: block1.txdata[2].compute_txid(), vout: 0 }).is_some()
        );
        assert!(store.get_coin(&seeded).is_none());
        assert!(store.get_undo(&block1_hash).is_some());
        assert_eq!(store.get_tip(), Some(block2_hash));
    }

    #[test]
    fn refuses_a_healthy_block() {
        let (store, block1, _block2_hash, _seeded) = make_holed_store();

        // Heal the hole first.
        repair_lost_connect_delta(
            &store,
            &block1,
            &NoopVerifier,
            Network::Regtest,
            1,
            &AddressIndexConfig::default(),
            true,
        )
        .unwrap();

        // A second invocation must refuse: the delta is present.
        let err = repair_lost_connect_delta(
            &store,
            &block1,
            &NoopVerifier,
            Network::Regtest,
            1,
            &AddressIndexConfig::default(),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, RepairError::SignatureMismatch(_)), "got: {err}");
    }

    #[test]
    fn refuses_when_damage_is_wider_than_one_block() {
        let (store, block1, _block2_hash, seeded) = make_holed_store();

        // Make the damage deeper: one of the block's prevouts is gone
        // too (a second lost delta below). The scalpel must abort.
        let mut batch = StoreBatch::default();
        batch.coin_removes.push((seeded, 50_000_000, 0));
        store.write_batch(batch).unwrap();

        let err = repair_lost_connect_delta(
            &store,
            &block1,
            &NoopVerifier,
            Network::Regtest,
            1,
            &AddressIndexConfig::default(),
            false,
        )
        .unwrap_err();
        match err {
            RepairError::SignatureMismatch(msg) => {
                assert!(msg.contains("missing"), "got: {msg}")
            }
            other => panic!("expected SignatureMismatch, got: {other}"),
        }
    }

    #[test]
    fn refuses_a_block_at_the_tip() {
        // A "hole" at the tip is not this failure mode (nothing
        // connected over it); the right fix there is a normal restart.
        let (store, block1, block2_hash, _seeded) = make_holed_store();
        // Point the tip at block 1 itself.
        let batch = StoreBatch { tip: Some(block1.block_hash()), ..Default::default() };
        store.write_batch(batch).unwrap();
        let _ = block2_hash;

        let err = repair_lost_connect_delta(
            &store,
            &block1,
            &NoopVerifier,
            Network::Regtest,
            1,
            &AddressIndexConfig::default(),
            false,
        )
        .unwrap_err();
        assert!(matches!(err, RepairError::SignatureMismatch(_)), "got: {err}");
    }
}
