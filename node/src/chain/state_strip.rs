//! Stripping one block's OP_RETURN payloads: [`ChainState::strip_block`].
//!
//! The strip worker (a later change) decides which blocks to strip and
//! when; this is the step it runs for each one, and what the test-only
//! `stripopreturns` RPC calls directly. Every gate on *whether* a block may
//! be stripped is checked here except its depth below the tip, which is the
//! worker's to judge.
//!
//! The order is what keeps a crash harmless at every point:
//!
//! 1. Plan without locks: read the bytes, check the block, build the record.
//! 2. Commit the record and make it durable.
//! 3. Under `accept_lock` and the flat-file lock, check that the block's
//!    entry still points where the plan read it and is still on the active
//!    chain, then zero and punch the spans.
//!
//! A crash after step 2 leaves a record over intact bytes, which reads fine
//! (the reader zero-fills the spans) and is punched by the next attempt. A
//! punch with no durable record could never happen, so punched bytes always
//! have a record to supply their txids.

use std::fs::OpenOptions;
use std::ops::Range;
use std::sync::atomic::Ordering;

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Block, BlockHash, Network};
use parking_lot::Mutex;

use super::ChainState;
use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
use crate::storage::flatfile::FlatFilePos;
use crate::storage::opreturn_strip::{
    self, StoredBlock, StrippedOutput, StrippedTx, StripRecord,
};
use crate::storage::punch::{self, PunchCaps, PunchError};
use crate::storage::{Store, StoreBatch, StoreError};
use crate::validation;

/// The environment variable a regtest test sets to `strip-after-record` to
/// abort the process once a record is durable and before anything is
/// punched. Ignored on every other chain.
pub const FAILPOINT_ENV: &str = "SATD_TEST_FAILPOINT";
const FAILPOINT_AFTER_RECORD: &str = "strip-after-record";

/// What [`ChainState::strip_block`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StripOutcome {
    /// No output in the block is eligible under the threshold.
    NothingEligible,
    /// The block had no record: one was written and its spans punched.
    Stripped(StripStats),
    /// A record already covered every eligible output. Its spans were
    /// punched again, which finishes a strip a crash interrupted.
    Redone(StripStats),
    /// The threshold is lower than the record's: the outputs newly eligible
    /// were added to the record and punched.
    Extended(StripStats),
    /// The block's entry moved, or the block left the active chain, between
    /// the plan and the punch. The record was put back as it was before
    /// this call and nothing was punched.
    Raced,
}

/// The spans one call punched.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StripStats {
    /// Transactions with a span punched by this call.
    pub txs: u64,
    pub outputs: u64,
    /// Bytes zeroed: each span's script length less its opcode.
    pub span_bytes: u64,
    /// Whole filesystem blocks inside those spans, in bytes. An upper bound
    /// on what was freed, not a measurement: a span punched before (a
    /// redo) counts again and frees nothing.
    pub freed_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum StripError {
    /// A gate on the whole node is closed: the reason names it.
    #[error("the node is not quiet: {0}")]
    NotQuiet(&'static str),
    #[error("block {0} is not in the block index")]
    UnknownBlock(BlockHash),
    #[error("block {0} is not on the active chain")]
    NotActive(BlockHash),
    #[error("block {hash} is {status:?}, not Valid")]
    NotValid { hash: BlockHash, status: BlockStatus },
    /// The stored copy fails a check. Raised as a `blockdata.corrupt.*`
    /// warning as well; a copy that does not verify is never stripped.
    #[error("block {hash} is not stripped, its stored copy is unusable: {detail}")]
    Corrupt { hash: BlockHash, detail: String },
    #[error(transparent)]
    Punch(#[from] PunchError),
    #[error("strip store write: {0}")]
    Store(#[from] StoreError),
    #[error("strip punch I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Strip state held by [`ChainState`].
#[derive(Default)]
pub(crate) struct StripState {
    /// One strip at a time. Two calls on one block could otherwise each
    /// plan against the other's half-written record. Taken before
    /// `accept_lock`, and never while holding it.
    lock: Mutex<()>,
    /// The blocks dir's punch capabilities, probed by the first strip.
    caps: Mutex<Option<PunchCaps>>,
    /// `-allowteststrip` on a regtest node: the `stripopreturns` RPC is
    /// registered.
    test_rpc: std::sync::atomic::AtomicBool,
    /// Runs between the plan and the record write, where anything that
    /// moves the block lands before the punch re-checks it.
    #[cfg(test)]
    pub(crate) after_plan_hook: Mutex<Option<Box<dyn FnOnce(&ChainState) + Send>>>,
}

/// The plan for punching one block.
struct Plan {
    entry: BlockIndexEntry,
    /// The record to commit, or `None` for a redo, which commits nothing.
    commit: Option<StripRecord>,
    /// The record bytes before this call, restored if the block moves.
    prior: Option<Vec<u8>>,
    /// Byte ranges to punch, relative to the block bytes.
    ranges: Vec<Range<usize>>,
    txs: u64,
    kind: fn(StripStats) -> StripOutcome,
}

impl ChainState {
    /// Register the test-only `stripopreturns` RPC (`-allowteststrip`).
    /// Ignored on every chain but regtest. Call before the RPC server
    /// starts.
    pub fn allow_test_strip(&self) {
        if self.network == Network::Regtest {
            self.strip.test_rpc.store(true, Ordering::Release);
        }
    }

    /// Whether [`Self::allow_test_strip`] took effect.
    pub fn test_strip_allowed(&self) -> bool {
        self.strip.test_rpc.load(Ordering::Acquire)
    }

    /// Strip the eligible OP_RETURN payloads of the block `hash` under
    /// `threshold`, the scriptPubKey length at or above which an output is
    /// stripped.
    ///
    /// Refuses unless the node is quiet (out of IBD, no AssumeUTXO
    /// background chainstate, normal write mode), the block is `Valid` and
    /// on the active chain, and its stored copy passes `check_block`. Its
    /// depth is not checked: that is the caller's to judge.
    pub fn strip_block(&self, hash: &BlockHash, threshold: u64) -> Result<StripOutcome, StripError> {
        let _strip = self.strip.lock.lock();
        self.check_quiet()?;
        let caps = self.punch_caps()?;
        // Everything the block's connect wrote is durable before any of its
        // bytes are touched, so crash recovery never reconnects it from disk.
        self.flush_durable()?;

        let Some(plan) = self.plan_strip(hash, threshold)? else {
            return Ok(StripOutcome::NothingEligible);
        };
        #[cfg(test)]
        if let Some(hook) = self.strip.after_plan_hook.lock().take() {
            hook(self);
        }
        if let Some(record) = &plan.commit {
            self.store.write_batch(StoreBatch {
                opreturn_strip_puts: vec![(*hash, record.encode())],
                ..Default::default()
            })?;
            // The record must be on disk before any byte is punched: holes
            // with no record would read back as a block with wrong txids.
            self.flush_durable()?;
        }
        self.strip_failpoint();

        let pos = FlatFilePos {
            file_number: plan.entry.file_number,
            data_pos: plan.entry.data_pos,
        };
        let (file, stats) = {
            // `prune_up_to`'s order: `accept_lock`, then the flat files.
            // Holding both, nothing can repoint, prune, disconnect or
            // invalidate the block until the punch is done.
            let _accept = self.accept_lock.lock();
            let flat_files = self.flat_files.lock();
            let now = self.store.get_block_index(hash);
            let unmoved = now.as_ref().is_some_and(|e| {
                e.file_number == plan.entry.file_number && e.data_pos == plan.entry.data_pos
            });
            let still_ours = unmoved
                && now.as_ref().is_some_and(|e| e.status == BlockStatus::Valid)
                && self.active_chain_contains(hash, plan.entry.height);
            if !still_ours {
                drop(flat_files);
                // A mover or a prune dropped the record in its own batch, so
                // a record left now was written after it and describes bytes
                // the entry no longer names. A block that left the active
                // chain in place keeps whatever was punched before this
                // call, so it keeps the record it had.
                let in_place = unmoved && now.as_ref().is_some_and(|e| e.status != BlockStatus::Pruned);
                let restore = if in_place { plan.prior } else { None };
                if plan.commit.is_some() {
                    let mut batch = StoreBatch::default();
                    match restore {
                        Some(bytes) => batch.opreturn_strip_puts.push((*hash, bytes)),
                        None => batch.opreturn_strip_removes.push(*hash),
                    }
                    self.store.write_batch(batch)?;
                }
                return Ok(StripOutcome::Raced);
            }
            let path = flat_files.blocks_dir().join(format!("blk{:05}.dat", pos.file_number));
            // The cached read handles are read-only; punch through a handle
            // of its own.
            let file = OpenOptions::new().write(true).open(&path)?;
            let base = u64::from(pos.data_pos) + 8;
            let mut stats = StripStats {
                txs: plan.txs,
                ..Default::default()
            };
            for range in &plan.ranges {
                if range.is_empty() {
                    continue;
                }
                let len = range.len() as u64;
                stats.freed_bytes += punch::zero_and_punch(&file, base + range.start as u64, len, &caps)?;
                stats.outputs += 1;
                stats.span_bytes += len;
            }
            (file, stats)
        };
        // Outside the locks. A punch lost to a crash is redone by the next
        // call: the record names the spans and the reader zero-fills them.
        file.sync_data()?;
        Ok((plan.kind)(stats))
    }

    fn check_quiet(&self) -> Result<(), StripError> {
        if self.is_initial_block_download() {
            return Err(StripError::NotQuiet("initial block download"));
        }
        if self.has_background() {
            // Background validation reads the blocks below the snapshot.
            return Err(StripError::NotQuiet("an AssumeUTXO background chainstate is validating"));
        }
        if self.bulk_load.load(Ordering::Acquire) {
            // IBD and the startup replays (-reindex, -reindex-chainstate,
            // -upgradechainstate) run in BulkLoad.
            return Err(StripError::NotQuiet("the chainstate is in bulk-load write mode"));
        }
        Ok(())
    }

    fn punch_caps(&self) -> Result<PunchCaps, StripError> {
        let mut caps = self.strip.caps.lock();
        if let Some(c) = *caps {
            return Ok(c);
        }
        let probed = punch::probe(&self.blocks_dir)?;
        *caps = Some(probed);
        Ok(probed)
    }

    /// Abort the process here when a regtest test asks to, through
    /// [`FAILPOINT_ENV`]. Ignored on every other chain.
    fn strip_failpoint(&self) {
        if self.network == Network::Regtest
            && std::env::var(FAILPOINT_ENV).is_ok_and(|v| v == FAILPOINT_AFTER_RECORD)
        {
            tracing::error!("{FAILPOINT_ENV}={FAILPOINT_AFTER_RECORD}: aborting with a durable strip record");
            std::process::abort();
        }
    }

    /// Steps 1 and 4 of the strip: read and check the block, and work out
    /// what to commit and punch. `None` when nothing is eligible.
    fn plan_strip(&self, hash: &BlockHash, threshold: u64) -> Result<Option<Plan>, StripError> {
        let entry = self.store.get_block_index(hash).ok_or(StripError::UnknownBlock(*hash))?;
        if entry.status != BlockStatus::Valid {
            return Err(StripError::NotValid {
                hash: *hash,
                status: entry.status,
            });
        }
        if !self.active_chain_contains(hash, entry.height) {
            return Err(StripError::NotActive(*hash));
        }
        let pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        let corrupt = |detail: String| {
            self.report_corrupt_block_data(hash, &entry, &pos, &detail);
            StripError::Corrupt { hash: *hash, detail }
        };
        let bytes = self
            .flat_files
            .lock()
            .read_block(&pos)
            .map_err(|e| corrupt(format!("read failed: {e}")))?;
        let spans = opreturn_strip::tx_spans(&bytes).map_err(|e| corrupt(format!("block bytes do not parse: {e}")))?;
        let prior = self.store.get_opreturn_strip(hash)?;
        match &prior {
            None => {
                let block: Block = deserialize(&bytes)
                    .map_err(|e| corrupt(format!("record does not deserialize: {e}")))?;
                if block.block_hash() != *hash {
                    return Err(corrupt(format!(
                        "record holds a different block ({}); the entry points at the wrong offset",
                        block.block_hash()
                    )));
                }
                // Never strip a copy that does not verify: the record's
                // txids would come from bytes that do not match the header.
                // This also refuses punched bytes whose record was lost.
                validation::block::check_block(&block, self.network, entry.height)
                    .map_err(|e| corrupt(format!("the stored copy fails check_block: {e:?}")))?;
                let Some((record, _filled)) = StripRecord::build(&bytes, &block, threshold)
                    .map_err(|e| corrupt(format!("strip record cannot be built: {e}")))?
                else {
                    return Ok(None);
                };
                let ranges = opreturn_strip::strip_ranges(&bytes, &record, &spans)
                    .map_err(|e| corrupt(format!("strip record does not fit: {e}")))?;
                Ok(Some(Plan {
                    entry,
                    txs: record.txs.len() as u64,
                    commit: Some(record),
                    prior,
                    ranges,
                    kind: StripOutcome::Stripped,
                }))
            }
            Some(prior_bytes) => {
                let record = StripRecord::decode(prior_bytes)
                    .map_err(|e| corrupt(format!("strip record does not decode: {e}")))?;
                let stored = StoredBlock::from_bytes(bytes.clone(), Some(record.clone()), hash)
                    .map_err(|e| corrupt(format!("strip record does not match the stored bytes: {e}")))?;
                let extended = extend_record(&stored, &record, threshold);
                if extended == record {
                    let ranges = opreturn_strip::strip_ranges(&bytes, &record, &spans)
                        .map_err(|e| corrupt(format!("strip record does not fit: {e}")))?;
                    return Ok(Some(Plan {
                        entry,
                        txs: record.txs.len() as u64,
                        commit: None,
                        prior,
                        ranges,
                        kind: StripOutcome::Redone,
                    }));
                }
                let mut extended = extended;
                let mut filled = bytes.clone();
                opreturn_strip::fill_spans(&mut filled, &extended, &spans)
                    .map_err(|e| corrupt(format!("extended strip record does not fit: {e}")))?;
                extended.filled_sha256 = sha256::Hash::hash(&filled).to_byte_array();
                // The newly recorded txids and wtxids come from bytes the old
                // record's filled hash pins, and that hash was taken from a
                // copy that passed `check_block` (witness commitment
                // included): the read above has already checked every byte.
                // What is left to check is the new record itself.
                StoredBlock::from_bytes(bytes.clone(), Some(extended.clone()), hash)
                    .map_err(|e| corrupt(format!("extended strip record does not verify: {e}")))?;
                let new_only = only_new(&extended, &record);
                let ranges = opreturn_strip::strip_ranges(&bytes, &new_only, &spans)
                    .map_err(|e| corrupt(format!("strip record does not fit: {e}")))?;
                Ok(Some(Plan {
                    entry,
                    txs: new_only.txs.len() as u64,
                    commit: Some(extended),
                    prior,
                    ranges,
                    kind: StripOutcome::Extended,
                }))
            }
        }
    }
}

/// `record` plus every output of `stored` eligible under `threshold` that
/// it does not name yet. A transaction already in the record keeps its
/// recorded txid and wtxid, since its bytes are already zeroed; one new to
/// it takes them from its bytes, which are still intact. `filled_sha256` is
/// left as the old record's; the caller recomputes it.
fn extend_record(stored: &StoredBlock, record: &StripRecord, threshold: u64) -> StripRecord {
    let mut txs: Vec<StrippedTx> = Vec::new();
    let eligible = opreturn_strip::eligible_outputs(&stored.block, threshold);
    let mut old = record.txs.iter().peekable();
    let mut new = eligible.into_iter().peekable();
    loop {
        let next_old = old.peek().map(|t| t.tx_index as usize);
        let next_new = new.peek().map(|(i, _)| *i);
        match (next_old, next_new) {
            (None, None) => break,
            (Some(o), n) if n.is_none_or(|n| o < n) => txs.push(old.next().unwrap().clone()),
            (o, Some(n)) if o.is_none_or(|o| n < o) => {
                let (i, vouts) = new.next().unwrap();
                let tx = &stored.block.txdata[i];
                let txid = tx.compute_txid();
                let wtxid = tx.compute_wtxid();
                txs.push(StrippedTx {
                    tx_index: i as u32,
                    txid,
                    wtxid: (wtxid.to_raw_hash() != txid.to_raw_hash()).then_some(wtxid),
                    outputs: vouts.into_iter().map(|v| output_of(stored, i, v)).collect(),
                });
            }
            _ => {
                // The same transaction in both: the union of its outputs.
                let mut tx = old.next().unwrap().clone();
                let (i, vouts) = new.next().unwrap();
                for v in vouts {
                    if !tx.outputs.iter().any(|o| o.vout == v) {
                        tx.outputs.push(output_of(stored, i, v));
                    }
                }
                tx.outputs.sort_by_key(|o| o.vout);
                txs.push(tx);
            }
        }
    }
    StripRecord {
        filled_sha256: record.filled_sha256,
        txs,
    }
}

fn output_of(stored: &StoredBlock, tx_index: usize, vout: u32) -> StrippedOutput {
    StrippedOutput {
        vout,
        script_len: stored.block.txdata[tx_index].output[vout as usize].script_pubkey.len() as u64,
    }
}

/// The outputs `extended` names that `old` does not, as a record: what an
/// extension has left to punch.
fn only_new(extended: &StripRecord, old: &StripRecord) -> StripRecord {
    let txs = extended
        .txs
        .iter()
        .filter_map(|tx| {
            let before = old.tx(tx.tx_index as usize);
            let outputs: Vec<StrippedOutput> = tx
                .outputs
                .iter()
                .filter(|o| before.is_none_or(|b| !b.outputs.iter().any(|p| p.vout == o.vout)))
                .cloned()
                .collect();
            (!outputs.is_empty()).then(|| StrippedTx {
                outputs,
                ..tx.clone()
            })
        })
        .collect();
    StripRecord {
        filled_sha256: extended.filled_sha256,
        txs,
    }
}

#[cfg(all(test, unix))]
#[path = "state_strip_tests.rs"]
mod tests;
