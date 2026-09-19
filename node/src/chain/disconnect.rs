use bitcoin::{Block, OutPoint};

use crate::index::address::AddressIndexConfig;
#[cfg(feature = "block-filter-index")]
use crate::index::filter::FilterIndexConfig;
use crate::storage::{Store, StoreBatch};
use crate::storage::undo::UndoData;

/// Errors returned by `disconnect_block` when the on-disk undo data
/// is inconsistent with the block being disconnected. Surfaced as a
/// real error so corrupt local state lands the operator on
/// `-reindex-chainstate` instead of an abort.
#[derive(Debug, thiserror::Error)]
pub enum DisconnectError {
    #[error("undo.spent_coins length {actual} does not match expected non-coinbase input count {expected} for block at height {height}")]
    UndoLengthMismatch {
        height: u32,
        expected: usize,
        actual: usize,
    },
    #[error("undo.spent_coins exhausted at height {height} while reconstructing spending tx {tx_idx} input {vin} (cursor {cursor}, len {len})")]
    UndoExhausted {
        height: u32,
        tx_idx: usize,
        vin: usize,
        cursor: usize,
        len: usize,
    },
}

/// Parameters for block disconnection. Mirrors
/// [`ConnectParams`](crate::chain::connect::ConnectParams): the inverse
/// operation needs the same index configuration plus the block's place in
/// the chain, and a positional argument list that long is unreadable at
/// the call site and easy to transpose.
pub struct DisconnectParams<'a> {
    /// Read-only store handle. Needed for one thing: an undo coin that
    /// came from an AssumeUTXO snapshot carries `TXSEQ_UNKNOWN`, and the
    /// `spent` row it needs to remove is keyed on the funding ordinal.
    /// The fallback is the same `tx_loc` lookup `connect_block` used to
    /// write the row, so the two agree on which rows exist.
    pub store: &'a dyn Store,
    pub block: &'a Block,
    pub undo: &'a UndoData,
    pub block_height: u32,
    pub prev_hash: bitcoin::BlockHash,
    /// The chain-order ordinal the block's first transaction took, i.e.
    /// the cumulative transaction count through its parent. The caller
    /// reads it from `chain_tx`, which is hash-keyed and so unaffected by
    /// the reorg that is removing this block.
    pub first_txseq: u64,
    pub address_index: &'a AddressIndexConfig,
    #[cfg(feature = "block-filter-index")]
    pub filter_index: &'a FilterIndexConfig,
    pub sp_index: &'a crate::index::silent_payments::SpIndexConfig,
}

/// Disconnect a block: reverse its effects on the UTXO set, the
/// transaction-ordinal families, and the address-history index.
///
/// Restores spent coins from undo data, removes created outputs,
/// removes the disconnected block's ordinal rows, and emits the
/// inverse address-index rows so a reorg leaves no stale state.
///
/// Coinbase txs are deliberately included in the ordinal removes —
/// they're recorded by `connect_block` for `getrawtransaction`
/// lookups and must be cleared on disconnect.
///
/// `undo.spent_coins` is in connect-order: each non-coinbase tx in
/// the block consumed `tx.input.len()` undo entries, in tx order.
/// We walk the txs forward in parallel with the undo cursor to
/// recover the `(spending_txid, vin)` for each entry — required
/// because `addr_spending` rows are keyed by the spending tx, not
/// the funding outpoint.
///
/// Returns an error rather than panicking when undo data is
/// truncated or oversized: a corrupt local store should surface as a
/// recoverable error so the operator can recover via
/// `-reindex-chainstate`, not abort the process.
pub fn disconnect_block(params: &DisconnectParams) -> Result<StoreBatch, DisconnectError> {
    #[cfg(feature = "block-filter-index")]
    let DisconnectParams {
        store,
        block,
        undo,
        block_height,
        prev_hash,
        first_txseq,
        address_index,
        filter_index,
        sp_index,
    } = params;
    #[cfg(not(feature = "block-filter-index"))]
    let DisconnectParams {
        store,
        block,
        undo,
        block_height,
        prev_hash,
        first_txseq,
        address_index,
        sp_index,
    } = params;
    let store: &dyn Store = *store;
    let block_height = *block_height;
    let prev_hash = *prev_hash;
    let first_txseq = *first_txseq;

    let mut batch = StoreBatch::default();

    // Walk forward to compute txids once and emit the address-index
    // spending-removes in the same pass. We then walk the txdata
    // again in reverse for the coin/funding removals (to match the
    // connect_block order's reversal).
    let txids: Vec<bitcoin::Txid> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();

    // Address-spending removes: the canonical correspondence between
    // undo entries and (spending tx, vin) pairs. Validated as a real
    // error so a corrupt undo file (truncated, oversized, or with
    // mismatched ordering after a future undo-format change) doesn't
    // panic the node mid-reorg.
    let expected_undo_count: usize = block
        .txdata
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .map(|tx| tx.input.len())
        .sum();
    if undo.spent_coins.len() != expected_undo_count {
        return Err(DisconnectError::UndoLengthMismatch {
            height: block_height,
            expected: expected_undo_count,
            actual: undo.spent_coins.len(),
        });
    }

    let mut undo_cursor = 0usize;
    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        if tx.is_coinbase() {
            continue;
        }
        for (vin, input) in tx.input.iter().enumerate() {
            let coin = undo.spent_coins.get(undo_cursor).ok_or(
                DisconnectError::UndoExhausted {
                    height: block_height,
                    tx_idx,
                    vin,
                    cursor: undo_cursor,
                    len: undo.spent_coins.len(),
                },
            )?;
            if let Some(key) = crate::index::address::spending_remove_key(
                address_index,
                first_txseq + tx_idx as u64,
                vin as u32,
                coin,
            ) {
                batch.addr_spending_removes.push(key);
            }
            // spent remove: keyed by the ordinal of the transaction
            // that created the consumed output. The undo coin carries
            // it, exactly as the live coin did when `connect_block`
            // wrote the row.
            //
            // A `TXSEQ_UNKNOWN` coin falls back to the same lookup the
            // connect path used; a `None` there means no row was written
            // in the first place, so no remove is emitted. Emitting one
            // anyway would be harmless against RocksDB but would hide
            // the asymmetry from the batch, and the merge dedup reasons
            // about named keys.
            if address_index.enabled {
                let funding_txseq = if coin.txseq != node_index::TXSEQ_UNKNOWN {
                    Some(coin.txseq)
                } else {
                    store.get_tx_seq(&input.previous_output.txid)
                };
                if let Some(funding_txseq) = funding_txseq
                    && let Some(key) = crate::index::outpoint_spend::emit::remove_key(
                        address_index,
                        funding_txseq,
                        input.previous_output.vout,
                    )
                {
                    batch.spent_removes.push(key);
                }
            }
            // Restore the spent coin. The outpoint is the input's
            // previous_output (the v1 undo format omits outpoints because
            // of exactly this invariant: undo entries are in connect-
            // order, one per non-coinbase input).
            batch
                .coin_puts
                .push((input.previous_output, coin.clone()));
            undo_cursor += 1;
        }
    }

    // Remove outputs created by this block (in reverse order so that
    // intra-block-spend dependencies disappear before their parents).
    for (tx_idx_rev, tx) in block.txdata.iter().enumerate().rev() {
        let txid = txids[tx_idx_rev];
        for (vout, output) in tx.output.iter().enumerate() {
            // Symmetric with `connect_block`: provably-unspendable
            // outputs were never added to the UTXO set (nor the address
            // index), so they must not be removed here. Removing a coin
            // that was never inserted would wrongly decrement the
            // UTXO counter/histogram and push a spurious address-index
            // funding-remove. See `connect::is_unspendable`.
            if crate::chain::connect::is_unspendable(&output.script_pubkey) {
                continue;
            }
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            batch
                .coin_removes
                .push((outpoint, output.value.to_sat(), block_height));

            // Address-history funding remove for this output, keyed on
            // the same ordinal `connect_block` wrote it under.
            if let Some(key) = crate::index::address::funding_remove_key(
                address_index,
                first_txseq + tx_idx_rev as u64,
                vout as u32,
                output,
            ) {
                batch.addr_funding_removes.push(key);
            }
        }

        // Ordinal removes: every txid in the block had a `tx_loc` and a
        // `txseq_txid` row written by `connect_block`. Removing them
        // here is the fix for the long-standing bug documented at
        // `test_disconnect_txindex_removes` in this module's tests —
        // before it, disconnected blocks left stale mappings that
        // `getrawtransaction` would still resolve.
        //
        // Explicit keys, never a range delete: the replacement chain
        // reuses this ordinal range immediately, and `StoreBatch::merge`
        // resolves a put and a remove on the same key in the same
        // pending batch only when both are named.
        batch.tx_loc_removes.push(txid);
        batch
            .txseq_txid_removes
            .push(first_txseq + tx_idx_rev as u64);
    }

    // The block's own ordinal-range row.
    batch.txseq_block_removes.push(first_txseq);

    // Update tip to previous block and clean height index
    // (coin restoration happens in the input-walk above — the v1 undo
    // format relies on input order for outpoint recovery, so we restore
    // coins in the same pass that walks the tx inputs).
    batch.tip = Some(prev_hash);
    batch.height_hash_removes.push(block_height);

    // BIP 158 filter index: drop the filter blob + chained header for
    // this height. Both rows live under `(FILTER_TYPE_BASIC, height)`
    // so a single key drops both. Reorg correctness comes from the
    // `(type, height)` keying — a subsequent connect of a different
    // block at the same height overwrites the row deterministically.
    #[cfg(feature = "block-filter-index")]
    if let Some(key) = crate::index::filter::filter_remove_key(filter_index, block_height) {
        batch.filter_removes.push(key);
    }

    // BIP 352 tweak index: drop this height's row. Keyed by height, so a
    // single entry drops the block's tweak row; a subsequent connect of a
    // different block at the same height overwrites it deterministically.
    // A remove for a height with no row (e.g. below taproot activation) is
    // a harmless no-op delete.
    if sp_index.enabled {
        batch.sp_tweak_removes.push(block_height);
    }

    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::connect::{block_subsidy, connect_block, ConnectParams};
    use crate::storage::coinview::Coin;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFilePos;
    use crate::storage::undo::UndoData;
    use crate::storage::{Store, StoreBatch};
    use crate::validation::script::NoopVerifier;
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, Block, BlockHash, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    // ── helpers (duplicated from connect.rs tests, since those are private) ──

    /// Create an InMemoryStore pre-loaded with a single coin.
    fn make_test_store_with_coin(
        coin_height: u32,
        coinbase: bool,
    ) -> (InMemoryStore, OutPoint, Coin) {
        let store = test_store();
        let txid = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x42; 32]),
        );
        let outpoint = OutPoint { txid, vout: 0 };
        let coin = Coin {
            amount: 50_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: coin_height,
            coinbase,
            txseq: node_index::TXSEQ_UNKNOWN,
        };

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((outpoint, coin.clone()));
        store.write_batch(batch).unwrap();

        (store, outpoint, coin)
    }

    /// Build a block with a coinbase and a spending tx that consumes `outpoint`.
    fn make_block_spending(
        outpoint: OutPoint,
        height: u32,
        tx_version: i32,
        sequence: u32,
        locktime: u32,
    ) -> Block {
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();
        let coinbase = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(block_subsidy(Network::Regtest, height)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let spending_tx = Transaction {
            version: Version(tx_version),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(locktime),
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence(sequence),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let txdata = vec![coinbase, spending_tx];
        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
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

    /// Build a coinbase-only block at the given height.
    fn make_coinbase_only_block(height: u32, prev_blockhash: BlockHash) -> Block {
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();
        let coinbase = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(block_subsidy(Network::Regtest, height)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let txdata = vec![coinbase];
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

    fn default_pos() -> FlatFilePos {
        FlatFilePos {
            file_number: 0,
            data_pos: 0,
        }
    }

    /// Add a coin to the store at a specific outpoint.
    fn add_coin_to_store(store: &InMemoryStore, outpoint: OutPoint, coin: Coin) {
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((outpoint, coin));
        store.write_batch(batch).unwrap();
    }

    /// Make a unique OutPoint from a single-byte seed.
    fn make_outpoint(seed: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([seed; 32]),
            ),
            vout,
        }
    }

    // ── tests ────────────────────────────────────────────────────────────

    /// An `InMemoryStore` whose cumulative-transaction-count series is
    /// seeded for the synthetic parents these fixtures use.
    ///
    /// Since schema 4 `connect_block` fails closed on a parent with no
    /// `chain_tx` row: the ordinal every index row is keyed on is
    /// `chain_tx(parent) + position`, so a gap would number the block
    /// from zero and mis-key its rows. These fixtures build blocks with
    /// a placeholder `prev_blockhash`, so seeding the series is the
    /// fixture's job, exactly as seeding the parent's coins already is.
    fn test_store() -> InMemoryStore {
        let store = InMemoryStore::new();
        let mut batch = StoreBatch::default();
        batch.chain_tx_puts.push((BlockHash::all_zeros(), 0));
        batch.chain_tx_puts.push((
            bitcoin::constants::genesis_block(Network::Regtest).block_hash(),
            1,
        ));
        store.write_batch(batch).unwrap();
        store
    }

    #[test]
    fn test_disconnect_coinbase_only() {
        // Connect a coinbase-only block at height 1, then disconnect it.
        let store = test_store();
        let prev_hash = BlockHash::all_zeros();
        let block = make_coinbase_only_block(1, prev_hash);
        let block_hash = block.block_hash();

        let connect_batch =
            connect_block(&ConnectParams {
                replay_plan: None,
                store: &store,
                block: &block,
                height: 1,
                parent_chainwork: &[0u8; 32],
                flat_pos: default_pos(),
                script_verifier: &NoopVerifier,
                median_time_past: 0,
                network: Network::Regtest,
                pre_verified_txs: None,
                num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
            })
                .unwrap();

        // Extract undo data (for non-genesis coinbase-only blocks, undo has no spent coins)
        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap_or_default();

        store.write_batch(connect_batch).unwrap();

        let store = test_store();
        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash,
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();

        // coin_removes should contain the coinbase output(s)
        let coinbase_txid = block.txdata[0].compute_txid();
        assert!(
            batch
                .coin_removes
                .iter()
                .any(|(op, _, _)| op.txid == coinbase_txid && op.vout == 0),
            "coin_removes should contain the coinbase output"
        );

        // No spent coins to restore for a coinbase-only block
        assert!(
            batch.coin_puts.is_empty(),
            "coin_puts should be empty for a coinbase-only block (no inputs spent)"
        );

        // Tip should be set to prev_hash
        assert_eq!(batch.tip, Some(prev_hash));
    }

    /// SP index write path: connect stamps a row per block (present even
    /// when empty), disconnect drops it, reconnect restores an identical
    /// row, and a disabled index writes nothing. Uses coinbase-only
    /// blocks — the tweak-contents correctness is proven against the
    /// BIP 352 vectors in `node-sp-index`; here we prove the plumbing.
    #[test]
    fn test_sp_index_connect_disconnect_reconnect() {
        use crate::index::silent_payments::SpIndexConfig;
        let sp_on = SpIndexConfig { enabled: true };

        let store = test_store();
        let prev_hash = BlockHash::all_zeros();
        let block = make_coinbase_only_block(1, prev_hash);
        let block_hash = block.block_hash();

        let connect = |sp: &SpIndexConfig| {
            connect_block(&ConnectParams {
                replay_plan: None,
                store: &store,
                block: &block,
                height: 1,
                parent_chainwork: &[0u8; 32],
                flat_pos: default_pos(),
                script_verifier: &NoopVerifier,
                median_time_past: 0,
                network: Network::Regtest,
                pre_verified_txs: None,
                num_threads: 1,
                precomputed_txids: None,
                address_index: &Default::default(),
                sp_index: sp,
                #[cfg(feature = "block-filter-index")]
                filter_index: &Default::default(),
                phase_tracker: None,
            })
            .unwrap()
        };

        // Enabled: one row at height 1 (regtest taproot activation = 0),
        // present but empty (coinbase-only block has no eligible tx), and
        // carrying the block's own hash — self-authenticating.
        let batch = connect(&sp_on);
        assert_eq!(batch.sp_tweak_puts.len(), 1);
        assert_eq!(batch.sp_tweak_puts[0].0, 1);
        store.write_batch(batch).unwrap();
        let row = store.get_sp_tweaks_row(1).expect("row present after connect");
        assert_eq!(row.block_hash, block_hash);
        assert!(row.entries.is_empty());

        // Disconnect drops the row.
        let undo = UndoData::default();
        let disc = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash,
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &sp_on,
        })
        .unwrap();
        assert_eq!(disc.sp_tweak_removes, vec![1]);
        store.write_batch(disc).unwrap();
        assert!(
            store.get_sp_tweaks_row(1).is_none(),
            "row gone after disconnect"
        );

        // Reconnect restores a byte-identical row.
        let rebatch = connect(&sp_on);
        store.write_batch(rebatch).unwrap();
        let row2 = store
            .get_sp_tweaks_row(1)
            .expect("row present after reconnect");
        assert_eq!(row2, row, "reconnected row identical to the original");
    }

    /// Flag off ⇒ zero behavior change: connect emits no SP rows and
    /// disconnect removes none.
    #[test]
    fn test_sp_index_disabled_emits_nothing() {
        let store = test_store();
        let prev_hash = BlockHash::all_zeros();
        let block = make_coinbase_only_block(1, prev_hash);

        let batch = connect_block(&ConnectParams {
            replay_plan: None,
            store: &store,
            block: &block,
            height: 1,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
        })
        .unwrap();
        assert!(
            batch.sp_tweak_puts.is_empty(),
            "disabled index emits no rows"
        );
        store.write_batch(batch).unwrap();
        assert!(store.get_sp_tweaks_row(1).is_none());

        let disc = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &UndoData::default(),
            block_height: 1,
            prev_hash,
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        })
        .unwrap();
        assert!(
            disc.sp_tweak_removes.is_empty(),
            "disabled index removes nothing"
        );
    }

    #[test]
    fn test_disconnect_spending_block() {
        // Create a store with a spendable coin, connect a block spending it, then disconnect.
        let (store, outpoint, _original_coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();
        let prev_hash = BlockHash::all_zeros();

        let connect_batch =
            connect_block(&ConnectParams {
                replay_plan: None,
                store: &store,
                block: &block,
                height: 1,
                parent_chainwork: &[0u8; 32],
                flat_pos: default_pos(),
                script_verifier: &NoopVerifier,
                median_time_past: 0,
                network: Network::Regtest,
                pre_verified_txs: None,
                num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
            })
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash,
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();

        // The spent coin should be restored
        assert_eq!(batch.coin_puts.len(), 1, "should restore exactly one spent coin");
        assert_eq!(batch.coin_puts[0].0, outpoint);

        // All outputs from both txs should be removed
        let spending_txid = block.txdata[1].compute_txid();
        let coinbase_txid = block.txdata[0].compute_txid();
        assert!(
            batch.coin_removes.iter().any(|(op, _, _)| op.txid == spending_txid),
            "spending tx outputs should be in coin_removes"
        );
        assert!(
            batch.coin_removes.iter().any(|(op, _, _)| op.txid == coinbase_txid),
            "coinbase outputs should be in coin_removes"
        );

        // The spend remove for the consumed UTXO must be present so the
        // row written by connect_block doesn't survive a reorg. Keyed by
        // the funding ordinal, which the undo coin carries — this
        // fixture's coin is `TXSEQ_UNKNOWN` with no `tx_loc` row, the
        // AssumeUTXO shape, so no row was written and none is removed.
        // `disconnect_removes_the_spent_row_of_a_reorged_spend` covers
        // the resolvable case.
        assert!(
            batch.spent_removes.is_empty(),
            "an unresolvable funding ordinal must skip the remove, not \
             name some other transaction's output"
        );
    }

    #[test]
    fn test_disconnect_restores_correct_amounts() {
        // Verify the restored coin has the exact same amount and script_pubkey.
        let (store, outpoint, original_coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();
        let prev_hash = BlockHash::all_zeros();

        let connect_batch =
            connect_block(&ConnectParams {
                replay_plan: None,
                store: &store,
                block: &block,
                height: 1,
                parent_chainwork: &[0u8; 32],
                flat_pos: default_pos(),
                script_verifier: &NoopVerifier,
                median_time_past: 0,
                network: Network::Regtest,
                pre_verified_txs: None,
                num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
            })
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash,
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();

        let (restored_op, restored_coin) = &batch.coin_puts[0];
        assert_eq!(*restored_op, outpoint);
        assert_eq!(restored_coin.amount, original_coin.amount);
        assert_eq!(restored_coin.script_pubkey, original_coin.script_pubkey);
        assert_eq!(restored_coin.height, original_coin.height);
        assert_eq!(restored_coin.coinbase, original_coin.coinbase);
    }

    #[test]
    fn test_disconnect_height_index_cleaned() {
        let block = make_coinbase_only_block(5, BlockHash::all_zeros());
        let undo = UndoData::default();

        let store = test_store();
        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 5,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();

        assert_eq!(batch.height_hash_removes, vec![5]);
    }

    #[test]
    fn test_disconnect_tip_set_to_prev() {
        let prev_hash = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
        );
        let block = make_coinbase_only_block(3, prev_hash);
        let undo = UndoData::default();

        let store = test_store();
        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 3,
            prev_hash,
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();

        assert_eq!(batch.tip, Some(prev_hash));
    }

    #[test]
    fn test_disconnect_multi_tx() {
        // Block with coinbase + 2 spending transactions.
        // We need 2 coins in the store.
        let store = test_store();
        let op1 = make_outpoint(0x10, 0);
        let op2 = make_outpoint(0x20, 0);
        let coin1 = Coin {
            amount: 30_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        let coin2 = Coin {
            amount: 20_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        add_coin_to_store(&store, op1, coin1.clone());
        add_coin_to_store(&store, op2, coin2.clone());

        // Build block: coinbase + tx1 (spends op1) + tx2 (spends op2)
        let height = 1u32;
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();
        let coinbase_tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(block_subsidy(Network::Regtest, height)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let tx1 = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op1,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(30_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let tx2 = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op2,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(20_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase_tx, tx1, tx2],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let block_hash = block.block_hash();
        let connect_batch =
            connect_block(&ConnectParams {
                replay_plan: None,
                store: &store,
                block: &block,
                height,
                parent_chainwork: &[0u8; 32],
                flat_pos: default_pos(),
                script_verifier: &NoopVerifier,
                median_time_past: 0,
                network: Network::Regtest,
                pre_verified_txs: None,
                num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
            })
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: height,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();

        // All 3 txs' outputs should be in coin_removes
        // coinbase has 1 output, tx1 has 1, tx2 has 1 = 3 total
        assert_eq!(batch.coin_removes.len(), 3);

        // The 2 spent coins should be restored
        assert_eq!(batch.coin_puts.len(), 2);
        let restored_ops: Vec<OutPoint> = batch.coin_puts.iter().map(|(op, _)| *op).collect();
        assert!(restored_ops.contains(&op1));
        assert!(restored_ops.contains(&op2));
    }

    #[test]
    fn test_disconnect_multi_input_tx() {
        // Single tx spending 3 different inputs.
        let store = test_store();
        let op1 = make_outpoint(0x31, 0);
        let op2 = make_outpoint(0x32, 0);
        let op3 = make_outpoint(0x33, 0);
        let coin = Coin {
            amount: 10_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        add_coin_to_store(&store, op1, coin.clone());
        add_coin_to_store(&store, op2, coin.clone());
        add_coin_to_store(&store, op3, coin.clone());

        let height = 1u32;
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();
        let coinbase_tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(block_subsidy(Network::Regtest, height)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let multi_input_tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: op1,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: op2,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: op3,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(30_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase_tx, multi_input_tx],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let block_hash = block.block_hash();
        let connect_batch =
            connect_block(&ConnectParams {
                replay_plan: None,
                store: &store,
                block: &block,
                height,
                parent_chainwork: &[0u8; 32],
                flat_pos: default_pos(),
                script_verifier: &NoopVerifier,
                median_time_past: 0,
                network: Network::Regtest,
                pre_verified_txs: None,
                num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
            })
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: height,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();

        // All 3 spent inputs should be restored
        assert_eq!(batch.coin_puts.len(), 3);
        let restored_ops: Vec<OutPoint> = batch.coin_puts.iter().map(|(op, _)| *op).collect();
        assert!(restored_ops.contains(&op1));
        assert!(restored_ops.contains(&op2));
        assert!(restored_ops.contains(&op3));
    }

    #[test]
    fn test_disconnect_preserves_other_utxos() {
        // After applying disconnect batch, UTXOs from other blocks remain untouched.
        let store = test_store();

        // Create an "other" coin that should survive the disconnect.
        let other_op = make_outpoint(0xee, 0);
        let other_coin = Coin {
            amount: 99_000_000,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            height: 0,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        add_coin_to_store(&store, other_op, other_coin.clone());

        // Create a spendable coin for the block.
        let spend_op = make_outpoint(0x42, 0);
        let spend_coin = Coin {
            amount: 50_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        add_coin_to_store(&store, spend_op, spend_coin);

        let block = make_block_spending(spend_op, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();

        let connect_batch =
            connect_block(&ConnectParams {
                replay_plan: None,
                store: &store,
                block: &block,
                height: 1,
                parent_chainwork: &[0u8; 32],
                flat_pos: default_pos(),
                script_verifier: &NoopVerifier,
                median_time_past: 0,
                network: Network::Regtest,
                pre_verified_txs: None,
                num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
            })
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        // The other coin should still be there after connect
        assert!(store.get_coin(&other_op).is_some());

        // Disconnect
        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();
        store.write_batch(batch).unwrap();

        // The other coin should still be present
        let recovered = store.get_coin(&other_op).unwrap();
        assert_eq!(recovered.amount, other_coin.amount);
        assert_eq!(recovered.script_pubkey, other_coin.script_pubkey);
    }

    #[test]
    fn test_disconnect_then_reconnect() {
        // Disconnect a block, apply the batch, then reconnect the same block.
        // Final state should match the original connected state.
        let (store, outpoint, _coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();
        let prev_hash = BlockHash::all_zeros();

        // Connect
        let connect_batch =
            connect_block(&ConnectParams {
                replay_plan: None,
                store: &store,
                block: &block,
                height: 1,
                parent_chainwork: &[0u8; 32],
                flat_pos: default_pos(),
                script_verifier: &NoopVerifier,
                median_time_past: 0,
                network: Network::Regtest,
                pre_verified_txs: None,
                num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
            })
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        // Save coin state after connect for comparison
        store.write_batch(connect_batch).unwrap();
        let coins_after_connect: Vec<(OutPoint, Coin)> = {
            // Collect all coins by checking known outpoints
            let mut coins = Vec::new();
            for tx in &block.txdata {
                let tid = tx.compute_txid();
                for vout in 0..tx.output.len() {
                    let op = OutPoint {
                        txid: tid,
                        vout: vout as u32,
                    };
                    if let Some(c) = store.get_coin(&op) {
                        coins.push((op, c));
                    }
                }
            }
            coins
        };
        // The original spent coin should be gone
        assert!(store.get_coin(&outpoint).is_none());

        // Disconnect
        let disconnect_batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash,
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();
        store.write_batch(disconnect_batch).unwrap();

        // After disconnect, the original coin should be back
        assert!(store.get_coin(&outpoint).is_some());

        // Reconnect
        let reconnect_batch =
            connect_block(&ConnectParams {
                replay_plan: None,
                store: &store,
                block: &block,
                height: 1,
                parent_chainwork: &[0u8; 32],
                flat_pos: default_pos(),
                script_verifier: &NoopVerifier,
                median_time_past: 0,
                network: Network::Regtest,
                pre_verified_txs: None,
                num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
            })
                .unwrap();
        store.write_batch(reconnect_batch).unwrap();

        // After reconnect, state should match original connected state
        assert!(store.get_coin(&outpoint).is_none(), "spent coin should be gone again");
        for (op, coin) in &coins_after_connect {
            let recovered = store.get_coin(op).expect("coin should exist after reconnect");
            assert_eq!(recovered.amount, coin.amount);
            assert_eq!(recovered.height, coin.height);
        }
    }

    #[test]
    fn test_disconnect_empty_undo() {
        // Coinbase-only block (not genesis) with empty undo data works fine.
        let prev_hash = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0xbb; 32]),
        );
        let block = make_coinbase_only_block(10, prev_hash);
        let undo = UndoData::default();

        let store = test_store();
        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 10,
            prev_hash,
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();

        // Should still remove coinbase outputs
        assert!(!batch.coin_removes.is_empty());
        // No coins to restore
        assert!(batch.coin_puts.is_empty());
        // Tip and height index should be updated
        assert_eq!(batch.tip, Some(prev_hash));
        assert_eq!(batch.height_hash_removes, vec![10]);
    }

    #[test]
    fn test_disconnect_removes_tx_index_entries() {
        // Verify the M2 fix: disconnect_block must populate tx_index_removes
        // so reorgs leave no stale txid -> block_hash mappings that
        // getrawtransaction would resolve. Before the M2 fix this test
        // asserted the BUG (empty tx_index_removes) — flipped to assert the
        // fix.
        let (store, outpoint, _coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();

        let connect_batch =
            connect_block(&ConnectParams {
                replay_plan: None,
                store: &store,
                block: &block,
                height: 1,
                parent_chainwork: &[0u8; 32],
                flat_pos: default_pos(),
                script_verifier: &NoopVerifier,
                median_time_past: 0,
                network: Network::Regtest,
                pre_verified_txs: None,
                num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
            })
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        // Sanity: connect populated tx_loc_puts for both txs (coinbase +
        // spending). Disconnect must remove both.
        let connected_txids: Vec<_> = connect_batch
            .tx_loc_puts
            .iter()
            .map(|(txid, _)| *txid)
            .collect();
        assert_eq!(
            connected_txids.len(),
            block.txdata.len(),
            "every block tx should have a tx_loc_puts entry"
        );

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        }).unwrap();

        // Every txid that was added by connect_block must be removed by
        // disconnect_block.
        for txid in &connected_txids {
            assert!(
                batch.tx_loc_removes.contains(txid),
                "tx_loc_removes should contain txid {txid} that connect_block added"
            );
        }
        assert_eq!(
            batch.tx_loc_removes.len(),
            block.txdata.len(),
            "tx_loc_removes should have one entry per block tx (incl. coinbase)"
        );
        // Both directions, and the block's own range row. Leaving the
        // reverse rows behind would strand ordinals the replacement
        // chain is about to reuse.
        assert_eq!(
            batch.txseq_txid_removes.len(),
            block.txdata.len(),
            "txseq_txid_removes should have one entry per block tx"
        );
        assert_eq!(
            batch.txseq_block_removes,
            vec![0],
            "the block's ordinal-range row must be removed too"
        );
    }

    /// A reorg has to take the spend row back out, and the key it is
    /// under is the funding ordinal the undo coin carries — the same
    /// one the connect path used to write it. The two have to agree, or
    /// the reorg strands a row pointing at a spend the chain no longer
    /// contains.
    #[test]
    fn disconnect_removes_the_spent_row_of_a_reorged_spend() {
        let store = test_store();
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0x42; 32]),
            ),
            vout: 0,
        };
        const FUNDING_SEQ: u64 = 55;
        let coin = Coin {
            amount: 50_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
            txseq: FUNDING_SEQ,
        };
        let mut seed = StoreBatch::default();
        seed.coin_puts.push((outpoint, coin.clone()));
        seed.tx_loc_puts.push((outpoint.txid, FUNDING_SEQ));
        seed.txseq_txid_puts.push((FUNDING_SEQ, outpoint.txid));
        store.write_batch(seed).unwrap();

        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();
        let cfg = crate::index::address::AddressIndexConfig::default();
        let connect_batch = connect_block(&ConnectParams {
            replay_plan: None,
            store: &store,
            block: &block,
            height: 1,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
            address_index: &cfg,
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
        })
        .unwrap();
        let written = connect_batch.spent_puts.clone();
        assert_eq!(written.len(), 1, "premise: connect wrote one spend row");
        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();
        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &cfg,
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        })
        .unwrap();

        assert_eq!(
            batch.spent_removes,
            vec![written[0].key()],
            "the remove must name exactly the key the connect wrote"
        );
    }

    #[test]
    fn test_disconnect_emits_addr_funding_and_spending_removes() {
        // disconnect_block populates addr_funding_removes for every
        // output the block created and addr_spending_removes for every
        // input it consumed. The deletion symmetry mirrors the
        // connect-block emission so the address index stays atomic
        // with the chainstate across reorgs.
        //
        // The coin has to carry a resolvable funding ordinal: since the
        // spending row's value names it, connect skips the row entirely
        // without one (the AssumeUTXO case, covered by
        // `connect_skips_spent_row_for_unknown_coin_without_tx_loc`).
        let (store, outpoint, _coin) = make_test_store_with_coin(0, false);
        const FUNDING_SEQ: u64 = 61;
        let mut seed = StoreBatch::default();
        seed.coin_puts.push((
            outpoint,
            Coin {
                amount: 50_000_000,
                script_pubkey: bitcoin::ScriptBuf::new(),
                height: 0,
                coinbase: false,
                txseq: FUNDING_SEQ,
            },
        ));
        seed.tx_loc_puts.push((outpoint.txid, FUNDING_SEQ));
        seed.txseq_txid_puts.push((FUNDING_SEQ, outpoint.txid));
        store.write_batch(seed).unwrap();

        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();
        let cfg = crate::index::address::AddressIndexConfig::default();

        let connect_batch = connect_block(&ConnectParams {
            replay_plan: None,
            store: &store,
            block: &block,
            height: 1,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
            address_index: &cfg,
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
        })
        .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        // connect_block must have emitted at least one funding row (for
        // the spending tx's output) and one spending row (for the input).
        let funding_count = connect_batch.addr_funding_puts.len();
        let spending_count = connect_batch.addr_spending_puts.len();
        assert!(funding_count >= 1, "expected at least one addr_funding_puts");
        assert_eq!(spending_count, 1, "expected exactly one addr_spending_puts");
        // Capture the exact keys, not just how many. Since the rows key
        // on transaction ordinals, a disconnect that emitted the right
        // *number* of removes under the wrong ordinals would strand
        // every row it was meant to take out and delete rows belonging
        // to some other block — and a count check passes either way.
        let funding_keys: std::collections::HashSet<_> = connect_batch
            .addr_funding_puts
            .iter()
            .map(|r| r.key())
            .collect();
        let spending_keys: std::collections::HashSet<_> = connect_batch
            .addr_spending_puts
            .iter()
            .map(|r| r.key())
            .collect();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &cfg,
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        })
        .unwrap();

        assert_eq!(
            batch
                .addr_funding_removes
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>(),
            funding_keys,
            "addr_funding_removes must name exactly the keys connect wrote"
        );
        assert_eq!(
            batch
                .addr_spending_removes
                .iter()
                .cloned()
                .collect::<std::collections::HashSet<_>>(),
            spending_keys,
            "addr_spending_removes must name exactly the keys connect wrote"
        );
    }

    #[test]
    fn test_disconnect_address_index_disabled_emits_no_addr_rows() {
        // When --addressindex=0 is in effect, neither connect nor
        // disconnect should populate the addr_* vectors. Verifies the
        // runtime opt-out path threads correctly through both code paths.
        let (store, outpoint, _coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();
        let disabled = crate::index::address::AddressIndexConfig {
            enabled: false,
            ..Default::default()
        };

        let connect_batch = connect_block(&ConnectParams {
            replay_plan: None,
            store: &store,
            block: &block,
            height: 1,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
            address_index: &disabled,
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
        })
        .unwrap();

        assert!(connect_batch.addr_funding_puts.is_empty());
        assert!(connect_batch.addr_spending_puts.is_empty());

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();
        store.write_batch(connect_batch).unwrap();

        let disc = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &disabled,
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        })
        .unwrap();
        assert!(disc.addr_funding_removes.is_empty());
        assert!(disc.addr_spending_removes.is_empty());
    }

    #[cfg(feature = "block-filter-index")]
    #[test]
    fn test_disconnect_with_filter_index_enabled_emits_remove_key() {
        // Filter index on: disconnect produces one (type, height) remove.
        use crate::index::filter::FILTER_TYPE_BASIC;
        let (store, outpoint, _coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        // Synthesize a minimal-but-correct undo for the block (one
        // spent coin per non-coinbase input).
        let undo = UndoData {
            spent_coins: vec![_coin],
        };
        let fcfg = crate::index::filter::FilterIndexConfig {
            enabled: true,
            peer_serve: false,
        };
        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 42,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &fcfg,
            sp_index: &Default::default(),
        })
        .unwrap();
        assert_eq!(batch.filter_removes.len(), 1);
        assert_eq!(batch.filter_removes[0].height, 42);
        assert_eq!(batch.filter_removes[0].filter_type, FILTER_TYPE_BASIC);
    }

    #[cfg(feature = "block-filter-index")]
    #[test]
    fn test_disconnect_with_filter_index_disabled_emits_no_remove_key() {
        let (store, outpoint, _coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let undo = UndoData {
            spent_coins: vec![_coin],
        };
        let batch = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 42,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &crate::index::filter::FilterIndexConfig::default(),
            sp_index: &Default::default(),
        })
        .unwrap();
        assert!(batch.filter_removes.is_empty());
    }

    #[test]
    fn test_disconnect_returns_error_on_corrupt_undo_length() {
        // Corrupt-undo: a real block expects N undo entries, but the
        // store hands us a truncated UndoData. disconnect_block must
        // surface this as DisconnectError, not panic the node.
        let (store, outpoint, _coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();

        let connect_batch = connect_block(&ConnectParams {
            replay_plan: None,
            store: &store,
            block: &block,
            height: 1,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
            address_index: &Default::default(),
            sp_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            phase_tracker: None,
        })
        .unwrap();
        let mut undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();
        // Truncate the undo to simulate on-disk corruption.
        undo.spent_coins.clear();

        let result = disconnect_block(&DisconnectParams {
            store: &store,
            block: &block,
            undo: &undo,
            block_height: 1,
            prev_hash: BlockHash::all_zeros(),
            first_txseq: 0,
            address_index: &Default::default(),
            #[cfg(feature = "block-filter-index")]
            filter_index: &Default::default(),
            sp_index: &Default::default(),
        });
        let err = match result {
            Ok(_) => panic!("truncated undo must surface as DisconnectError"),
            Err(e) => e,
        };
        match err {
            DisconnectError::UndoLengthMismatch {
                height,
                expected,
                actual,
            } => {
                assert_eq!(height, 1);
                assert_eq!(actual, 0);
                assert!(expected > 0);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn test_disconnect_via_chain_state() {
        // Use ChainState to build chain A1->A2, then B1->B2->B3 triggering reorg.
        // After reorg, verify the height index is correct for the B chain.
        use crate::chain::state::tests::build_test_block;
        use crate::chain::state::{AssumeValid, ChainState};
        use crate::storage::flatfile::FlatFileManager;

        let dir = std::env::temp_dir().join(format!(
            "satd-disconnect-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
        4,
        Default::default(),
        Default::default(),
            Default::default(),)
        .unwrap();

        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build chain A: genesis -> A1 -> A2
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1").hash();
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let _a2_hash = cs.accept_block(&a2).expect("accept A2").hash();

        // Build chain B: genesis -> B1 -> B2 -> B3 (more work => triggers reorg)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_003);
        let b1_hash = cs.accept_block(&b1).expect("accept B1").hash();
        let b2 = build_test_block(b1_hash, 2, 1_300_000_004);
        let b2_hash = cs.accept_block(&b2).expect("accept B2").hash();
        let b3 = build_test_block(b2_hash, 3, 1_300_000_005);
        let b3_hash = cs.accept_block(&b3).expect("accept B3").hash();

        // Tip should be B3
        assert_eq!(cs.tip_height(), 3);
        assert_eq!(cs.tip_hash(), b3_hash);

        // After reorg, height index should map to B-chain blocks
        assert_eq!(
            cs.get_block_hash_by_height(0),
            Some(genesis_hash),
            "height 0 should be genesis"
        );
        assert_eq!(
            cs.get_block_hash_by_height(1),
            Some(b1_hash),
            "height 1 should be B1 after reorg"
        );
        assert_eq!(
            cs.get_block_hash_by_height(2),
            Some(b2_hash),
            "height 2 should be B2 after reorg"
        );
        assert_eq!(
            cs.get_block_hash_by_height(3),
            Some(b3_hash),
            "height 3 should be B3 after reorg"
        );

        // A-chain heights should no longer map to A blocks
        // (height 1 and 2 were overwritten by B chain)
        assert_ne!(
            cs.get_block_hash_by_height(1),
            Some(a1_hash),
            "height 1 should NOT be A1 after reorg"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
