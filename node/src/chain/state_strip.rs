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

use bitcoin::consensus::encode::{deserialize, serialize};
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

#[cfg(test)]
pub(crate) type StripHook = Box<dyn FnOnce(&ChainState) + Send>;

/// Strip state held by [`ChainState`].
#[derive(Default)]
pub(crate) struct StripState {
    /// One strip at a time. Two calls on one block could otherwise each
    /// plan against the other's half-written record. Taken before
    /// `accept_lock`, and never while holding it. `invalidate_block` takes it
    /// too, so no record lands between its stripped-block check and its
    /// marks.
    pub(super) lock: Mutex<()>,
    /// The blocks dir's punch capabilities, probed by the first strip.
    caps: Mutex<Option<PunchCaps>>,
    /// `-allowteststrip` on a regtest node: the `stripopreturns` RPC is
    /// registered.
    test_rpc: std::sync::atomic::AtomicBool,
    /// `-pruneopreturn` and its companions, set once at startup when the
    /// option is on.
    config: std::sync::OnceLock<StripConfig>,
    /// `-pruneopreturnpeers`. Set whether or not the option is on: it applies
    /// to a node with stripped blocks even after the option is turned off.
    peers: std::sync::OnceLock<opreturn_strip::PrunePeers>,
    /// Some block has a strip record. Set at startup from the store and by
    /// every strip; cleared when the worker finds the last record gone with
    /// the option off ([`ChainState::finish_opreturn_unstrip`]).
    has_records: std::sync::atomic::AtomicBool,
    /// What the worker is doing, for `getopreturnpruneinfo`.
    worker: Mutex<WorkerStatus>,
    /// Bumped by [`ChainState::forget_strip_summary`], so by every record
    /// write and removal.
    changes: std::sync::atomic::AtomicU64,
    /// One more than the value of `changes` read before the option-off pass's
    /// last flush and recount; 0 before the first.
    counted: std::sync::atomic::AtomicU64,
    /// The records' totals and when they were added up.
    summary: Mutex<Option<(std::time::Instant, opreturn_strip::StripSummary)>>,
    /// The totals as last added up, however long ago: what `getblockchaininfo`
    /// reports, so it never reads the whole CF on the RPC executor.
    last_summary: Mutex<opreturn_strip::StripSummary>,
    /// [`ChainState::blocks_dir_usage`] and when it was taken.
    usage: Mutex<Option<(std::time::Instant, (u64, u64))>>,
    /// Runs between the plan's index read and its read of the bytes.
    #[cfg(test)]
    pub(crate) before_read_hook: Mutex<Option<StripHook>>,
    /// Runs between the plan and the record write, where anything that
    /// moves the block lands before the punch re-checks it.
    #[cfg(test)]
    pub(crate) after_plan_hook: Mutex<Option<StripHook>>,
}

/// What [`ChainState::plan_strip`] found to do.
enum Planned {
    Nothing,
    /// The block moved or went away while it was being read.
    Raced,
    Strip(Box<Plan>),
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
        self.strip_block_inner(hash, threshold, false)
    }

    /// [`Self::strip_block`]. `flushed`: the caller made the store durable
    /// after the block connected (the worker does once per pass, and every
    /// block it strips connected long before), so the first flush is skipped.
    fn strip_block_inner(&self, hash: &BlockHash, threshold: u64, flushed: bool) -> Result<StripOutcome, StripError> {
        let _strip = self.strip.lock.lock();
        self.check_quiet()?;
        let caps = self.punch_caps()?;
        // Everything the block's connect wrote is durable before any of its
        // bytes are touched, so crash recovery never reconnects it from disk.
        if !flushed {
            self.flush_durable()?;
        }

        let plan = match self.plan_strip(hash, threshold)? {
            Planned::Nothing => return Ok(StripOutcome::NothingEligible),
            Planned::Raced => return Ok(StripOutcome::Raced),
            Planned::Strip(plan) => *plan,
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
                    self.forget_strip_summary();
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
        if plan.commit.is_some() {
            self.strip.has_records.store(true, Ordering::Release);
            self.forget_strip_summary();
        }
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
    /// what to commit and punch.
    fn plan_strip(&self, hash: &BlockHash, threshold: u64) -> Result<Planned, StripError> {
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
        match self.plan_from(hash, threshold, &entry) {
            Err(StripError::Corrupt { hash, detail }) => {
                // The entry is read without locks, so a prune or a repair
                // can land between it and the bytes: a read that fails, or
                // finds another record, because the block went away or moved.
                // That is a race, not corruption, and must not raise a
                // warning nothing clears.
                let unchanged = self.store.get_block_index(&hash).is_some_and(|now| {
                    now.status == BlockStatus::Valid
                        && now.file_number == entry.file_number
                        && now.data_pos == entry.data_pos
                });
                if !unchanged {
                    return Ok(Planned::Raced);
                }
                let pos = FlatFilePos {
                    file_number: entry.file_number,
                    data_pos: entry.data_pos,
                };
                self.report_corrupt_block_data(&hash, &entry, &pos, &detail);
                Err(StripError::Corrupt { hash, detail })
            }
            other => other,
        }
    }

    /// [`Self::plan_strip`] once the entry passes its checks. A
    /// [`StripError::Corrupt`] here is not reported yet: the caller first
    /// rules out a race.
    fn plan_from(&self, hash: &BlockHash, threshold: u64, entry: &BlockIndexEntry) -> Result<Planned, StripError> {
        let entry = entry.clone();
        let pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        let corrupt = |detail: String| StripError::Corrupt { hash: *hash, detail };
        #[cfg(test)]
        if let Some(hook) = self.strip.before_read_hook.lock().take() {
            hook(self);
        }
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
                // Most blocks have nothing to strip: say so before the cost
                // of checking the whole block.
                if opreturn_strip::eligible_outputs(&block, threshold).is_empty() {
                    return Ok(Planned::Nothing);
                }
                // Never strip a copy that does not verify: the record's
                // txids would come from bytes that do not match the header.
                // This also refuses punched bytes whose record was lost.
                validation::block::check_block(&block, self.network, entry.height)
                    .map_err(|e| corrupt(format!("the stored copy fails check_block: {e:?}")))?;
                let Some((record, _filled)) = StripRecord::build(&bytes, &block, threshold)
                    .map_err(|e| corrupt(format!("strip record cannot be built: {e}")))?
                else {
                    return Ok(Planned::Nothing);
                };
                let ranges = opreturn_strip::strip_ranges(&bytes, &record, &spans)
                    .map_err(|e| corrupt(format!("strip record does not fit: {e}")))?;
                Ok(Planned::Strip(Box::new(Plan {
                    entry,
                    txs: record.txs.len() as u64,
                    commit: Some(record),
                    prior,
                    ranges,
                    kind: StripOutcome::Stripped,
                })))
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
                    return Ok(Planned::Strip(Box::new(Plan {
                        entry,
                        txs: record.txs.len() as u64,
                        commit: None,
                        prior,
                        ranges,
                        kind: StripOutcome::Redone,
                    })));
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
                Ok(Planned::Strip(Box::new(Plan {
                    entry,
                    txs: new_only.txs.len() as u64,
                    commit: Some(extended),
                    prior,
                    ranges,
                    kind: StripOutcome::Extended,
                })))
            }
        }
    }
}

/// `-pruneopreturn` and its companions, as the node runs with them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StripConfig {
    /// Blocks more than this deep are stripped; at least 288.
    pub depth: u32,
    /// Outputs whose scriptPubKey is at least this long are stripped.
    pub size_threshold: u64,
}

/// What the strip worker is doing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WorkerStatus {
    /// `-pruneopreturn` is off, or the worker has not started.
    #[default]
    Off,
    Running,
    /// Waiting for the node to go quiet; the reason names what it waits for.
    Paused(&'static str),
}

impl WorkerStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Running => "running",
            Self::Paused("initial block download") => "ibd",
            Self::Paused("an AssumeUTXO background chainstate is validating") => "background_validation",
            Self::Paused(_) => "reindex",
        }
    }
}

/// What one [`ChainState::strip_pass`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Heights examined.
    pub examined: u32,
    /// Blocks newly stripped or extended.
    pub stripped: u32,
    /// The pass stopped at its block limit with more to do.
    pub more: bool,
}

/// How long the records' totals are reused before they are added up again.
const SUMMARY_TTL: std::time::Duration = std::time::Duration::from_secs(10);
/// Meta is written at least this often during a pass, so a crash loses
/// little of the scan.
const META_EVERY: u32 = 64;

impl ChainState {
    /// Turn `-pruneopreturn` on with `config`. Call once, at startup.
    pub fn configure_opreturn_prune(&self, config: StripConfig) {
        let _ = self.strip.config.set(config);
    }

    /// Set `-pruneopreturnpeers`. Call once, at startup.
    pub fn set_opreturn_prune_peers(&self, peers: opreturn_strip::PrunePeers) {
        let _ = self.strip.peers.set(peers);
    }

    /// What a node with stripped blocks serves to peers.
    pub fn opreturn_prune_peers(&self) -> opreturn_strip::PrunePeers {
        self.strip.peers.get().copied().unwrap_or_default()
    }

    /// The `-pruneopreturn` configuration, when the option is on.
    pub fn opreturn_prune_config(&self) -> Option<StripConfig> {
        self.strip.config.get().copied()
    }

    /// Plan §2.9's predicate: the option is on, or some block is stripped.
    /// Records outlive the option, so a node with stripped blocks stays
    /// `NODE_NETWORK_LIMITED` after it is turned off.
    pub fn opreturn_prune_active(&self) -> bool {
        self.strip.config.get().is_some() || self.strip.has_records.load(Ordering::Acquire)
    }

    /// Read the store once at startup for whether any block is stripped.
    /// Call after [`Self::configure_opreturn_prune`]: with the option off
    /// and no record, the strip family is dropped, as the worker drops it
    /// when the last record goes (plan §11.5). That finishes a drop a crash
    /// interrupted, and frees a datadir that only ever held the worker's
    /// cursor.
    pub fn load_opreturn_strip_state(&self) -> Result<(), StoreError> {
        let (summary, records) = self.compute_strip_summary()?;
        // Every record counts here, read back or not: its block is stripped
        // on disk either way.
        self.strip.has_records.store(records > 0, Ordering::Release);
        if records == 0 && self.opreturn_prune_config().is_none() {
            self.store.drop_opreturn_strip_cf()?;
        }
        *self.strip.summary.lock() = Some((std::time::Instant::now(), summary));
        Ok(())
    }

    /// With the option off, the last strip record gone: drop the strip
    /// family and clear [`StripState::has_records`], so the node advertises
    /// `NODE_NETWORK` again on its next handshake and an older release can
    /// open the datadir (plan §11.5). Rechecks under the strip lock, which
    /// every record write takes. Returns whether it finished.
    pub(super) fn finish_opreturn_unstrip(&self) -> Result<bool, StoreError> {
        if self.opreturn_prune_config().is_some() {
            return Ok(false);
        }
        let _strip = self.strip.lock.lock();
        let (summary, records) = self.compute_strip_summary()?;
        if records > 0 {
            return Ok(false);
        }
        self.store.drop_opreturn_strip_cf()?;
        self.strip.has_records.store(false, Ordering::Release);
        *self.strip.summary.lock() = Some((std::time::Instant::now(), summary));
        *self.strip.usage.lock() = None;
        tracing::info!(
            "OP_RETURN restore complete: no block is stripped any more. The node serves the full chain \
             again (NODE_NETWORK) and its datadir is an ordinary one"
        );
        Ok(true)
    }

    /// The records' totals, and how many records there are, decodable or not.
    fn compute_strip_summary(&self) -> Result<(opreturn_strip::StripSummary, u64), StoreError> {
        let fs_block = self.opreturn_strip_fs_block().unwrap_or(4096);
        let mut summary = opreturn_strip::StripSummary::default();
        let mut records = 0u64;
        self.store.for_each_opreturn_strip(&mut |_, bytes| {
            records += 1;
            // An unreadable record is not counted; reading its block reports it.
            if let Ok(record) = StripRecord::decode(bytes) {
                summary.add(&record, fs_block);
            }
        })?;
        *self.strip.last_summary.lock() = summary;
        Ok((summary, records))
    }

    /// The block files' apparent and allocated bytes, `(st_size,
    /// st_blocks × 512)` summed over `blk*.dat`, from a stat walk cached for a
    /// minute. The difference is what holes (and filesystem compression) save.
    pub fn blocks_dir_usage(&self) -> std::io::Result<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let mut cached = self.strip.usage.lock();
        if let Some((at, usage)) = *cached
            && at.elapsed() < std::time::Duration::from_secs(60)
        {
            return Ok(usage);
        }
        let (mut apparent, mut allocated) = (0u64, 0u64);
        for entry in std::fs::read_dir(self.blocks_dir())? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !(name.starts_with("blk") && name.ends_with(".dat")) {
                continue;
            }
            let meta = entry.metadata()?;
            apparent += meta.len();
            allocated += meta.blocks() * 512;
        }
        *cached = Some((std::time::Instant::now(), (apparent, allocated)));
        Ok((apparent, allocated))
    }

    /// The strip records' totals, added up at most every ten seconds.
    pub fn opreturn_strip_summary(&self) -> Result<opreturn_strip::StripSummary, StoreError> {
        let mut cached = self.strip.summary.lock();
        if let Some((at, summary)) = *cached
            && at.elapsed() < SUMMARY_TTL
        {
            return Ok(summary);
        }
        let (summary, _) = self.compute_strip_summary()?;
        *cached = Some((std::time::Instant::now(), summary));
        Ok(summary)
    }

    /// Add the totals up again, as [`Self::opreturn_strip_summary`] would on
    /// a miss, and return how many records there are.
    fn opreturn_strip_summary_records(&self) -> Result<u64, StoreError> {
        let (summary, records) = self.compute_strip_summary()?;
        *self.strip.summary.lock() = Some((std::time::Instant::now(), summary));
        Ok(records)
    }

    /// The totals as last added up, without reading the store: at startup,
    /// after each worker pass that changed them, and by
    /// [`Self::opreturn_strip_summary`].
    pub fn opreturn_strip_summary_last(&self) -> opreturn_strip::StripSummary {
        *self.strip.last_summary.lock()
    }

    /// Whether `hash` has a strip record, for a caller about to remove it
    /// with other writes: it calls [`Self::forget_strip_summary`] after the
    /// write when so. One point read, and none on a node that has never
    /// stripped.
    pub(super) fn holds_strip_record(&self, hash: &BlockHash) -> bool {
        self.strip.has_records.load(Ordering::Acquire) && matches!(self.store.get_opreturn_strip(hash), Ok(Some(_)))
    }

    /// Drop the cached totals and the blocks directory's stat: a record was
    /// written or removed, and a span punched or filled in.
    pub(super) fn forget_strip_summary(&self) {
        self.strip.changes.fetch_add(1, Ordering::AcqRel);
        *self.strip.summary.lock() = None;
        *self.strip.usage.lock() = None;
    }

    /// The worker's stored cursor.
    pub fn opreturn_strip_meta(&self) -> Option<opreturn_strip::StripMeta> {
        self.store
            .opreturn_strip_meta()
            .ok()
            .flatten()
            .and_then(|b| opreturn_strip::StripMeta::decode(&b))
    }

    pub fn opreturn_strip_worker_status(&self) -> WorkerStatus {
        *self.strip.worker.lock()
    }

    /// The fs block size the punch probe found, once a strip or the startup
    /// probe has run.
    pub fn opreturn_strip_fs_block(&self) -> Option<u64> {
        self.strip.caps.lock().map(|c| c.fs_block)
    }

    /// Probe the blocks directory for hole punching (plan §2.5).
    pub fn probe_opreturn_strip(&self) -> Result<PunchCaps, StripError> {
        self.punch_caps()
    }

    /// One pass of the strip worker (plan §2.6): examine up to `max_blocks`
    /// heights from the stored cursor, strip what is eligible, and move the
    /// cursor. A lowered size threshold starts the scan over, since outputs
    /// between the two sizes are newly eligible in blocks already examined; a
    /// raised one keeps it, and what is stripped stays stripped.
    pub fn strip_pass(&self, max_blocks: u32, stop: &std::sync::atomic::AtomicBool) -> Result<PassReport, StripError> {
        let Some(config) = self.opreturn_prune_config() else {
            // The option is off on a node that holds stripped blocks: nothing
            // to strip, but records go (`-prune`, `getblockfrompeer`, a fresh
            // copy), and the last one going finishes the job. After any
            // change since the last count: flush, then count. A remove that
            // rides a coin batch waits in the cache until a flush, and a
            // count taken before it still sees its record. The change counter
            // is read before the flush, so a removal that lands during this
            // pass is counted on the next.
            *self.strip.worker.lock() = WorkerStatus::Off;
            let changes = self.strip.changes.load(Ordering::Acquire);
            if self.strip.counted.load(Ordering::Acquire) != changes + 1 {
                self.flush_durable()?;
                // Marked counted only once the finish, when due, has run: a
                // finish that fails is retried by the next pass, since no
                // later change would come to prompt one.
                if self.opreturn_strip_summary_records()? == 0 {
                    self.finish_opreturn_unstrip()?;
                }
                self.strip.counted.store(changes + 1, Ordering::Release);
            }
            return Ok(PassReport::default());
        };
        if let Err(StripError::NotQuiet(why)) = self.check_quiet() {
            *self.strip.worker.lock() = WorkerStatus::Paused(why);
            return Ok(PassReport::default());
        }
        *self.strip.worker.lock() = WorkerStatus::Running;
        // Every block a pass reaches connected long before it: once makes all
        // of them durable.
        self.flush_durable()?;

        // A store error ends the pass rather than reading as "no cursor",
        // which would start the scan over from genesis.
        let stored = self.store.opreturn_strip_meta()?.and_then(|b| opreturn_strip::StripMeta::decode(&b));
        let mut meta = stored.unwrap_or(opreturn_strip::StripMeta {
            next_height: 0,
            size_threshold: config.size_threshold,
            depth: config.depth,
            last_hash: None,
        });
        if meta.size_threshold > config.size_threshold {
            meta.next_height = 0;
            meta.last_hash = None;
        }
        self.rewind_strip_cursor(&mut meta);
        meta.size_threshold = config.size_threshold;
        meta.depth = config.depth;

        let mut report = PassReport::default();
        // Strip only below `tip - N - 2` (plan §2.4): never a block a limited
        // peer may still ask for.
        let last = self.tip_height().checked_sub(config.depth.saturating_add(3));
        let result = (|| {
            let Some(last) = last else {
                return Ok(());
            };
            while meta.next_height <= last {
                if report.examined == max_blocks {
                    report.more = true;
                    return Ok(());
                }
                if stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
                let h = meta.next_height;
                // The tip fell below `h` since `last` was read: stop, and
                // examine the block that replaces it on a later pass.
                let Some(hash) = self.active_chain_hash_at_height_indexed(h) else {
                    return Ok(());
                };
                match self.strip_block_inner(&hash, config.size_threshold, true) {
                    Ok(StripOutcome::Stripped(_) | StripOutcome::Extended(_)) => report.stripped += 1,
                    Ok(_) => {}
                    Err(StripError::NotQuiet(why)) => {
                        *self.strip.worker.lock() = WorkerStatus::Paused(why);
                        return Ok(());
                    }
                    // Not a block to strip (yet), or a stored copy that
                    // does not verify, which has raised its warning: move
                    // on rather than wedge the scan on it.
                    Err(e @ (StripError::UnknownBlock(_)
                    | StripError::NotActive(_)
                    | StripError::NotValid { .. }
                    | StripError::Corrupt { .. })) => {
                        tracing::debug!(height = h, error = %e, "OP_RETURN strip: skipping block");
                    }
                    Err(e) => return Err(e),
                }
                meta.next_height = h + 1;
                meta.last_hash = Some(hash);
                report.examined += 1;
                if report.examined % META_EVERY == 0 {
                    self.write_strip_meta(&meta)?;
                }
            }
            Ok(())
        })();
        self.write_strip_meta(&meta)?;
        // A strip or a restore dropped the cached totals: add them up here,
        // off the RPC path, for `getblockchaininfo`.
        if self.strip.summary.lock().is_none() {
            let _ = self.opreturn_strip_summary();
        }
        result.map(|()| report)
    }

    /// Move the cursor back to the fork point when the block it examined last
    /// is no longer on the active chain: a reorg replaced blocks below it,
    /// and the ones now at those heights have not been examined. Such a reorg
    /// never crosses a stripped block (it would be refused), so it only
    /// costs a rescan of the replaced heights.
    fn rewind_strip_cursor(&self, meta: &mut opreturn_strip::StripMeta) {
        let Some(mut hash) = meta.last_hash else {
            meta.next_height = 0;
            return;
        };
        let Some(mut height) = meta.next_height.checked_sub(1) else {
            meta.last_hash = None;
            return;
        };
        while !self.active_chain_contains(&hash, height) {
            match self.get_block_index(&hash) {
                Some(entry) if height > 0 => {
                    hash = entry.header.prev_blockhash;
                    height -= 1;
                }
                // Not in the index, or a genesis that is not ours: start over.
                _ => {
                    meta.next_height = 0;
                    meta.last_hash = None;
                    return;
                }
            }
        }
        if height + 1 != meta.next_height {
            tracing::info!(
                from = meta.next_height,
                to = height + 1,
                "OP_RETURN strip: a reorg replaced examined blocks; rescanning from the fork"
            );
        }
        meta.next_height = height + 1;
        meta.last_hash = Some(hash);
    }

    fn write_strip_meta(&self, meta: &opreturn_strip::StripMeta) -> Result<(), StoreError> {
        self.store.write_batch(StoreBatch {
            opreturn_strip_meta: Some(meta.encode()),
            ..Default::default()
        })
    }

    /// Restore an OP_RETURN-stripped block in place from `block`, a full copy
    /// that [`Self::repair_block_data`] has already checked at `height`
    /// (plan §2.12). The whole body is rewritten over the stripped one, then
    /// the record is removed: no second copy, no new slack, and the punched
    /// spans are allocated again.
    ///
    /// `None` when the block has no record, or when the copy cannot go back
    /// where the stripped one is: the stored length does not match, or the
    /// record does not describe this block. The caller then appends a copy,
    /// as for any other damaged block, and drops the record with it.
    ///
    /// Takes the strip lock first, so no strip of this block runs between the
    /// write and the record's removal: a redo, which writes no record, would
    /// otherwise punch bytes whose record had just gone.
    pub(super) fn restore_stripped_in_place(
        &self,
        block: &Block,
        height: u32,
    ) -> Result<Option<super::BlockDataRepair>, super::ChainError> {
        let hash = block.block_hash();
        let _strip = self.strip.lock.lock();
        let Some(record_bytes) = self.store.get_opreturn_strip(&hash)? else {
            return Ok(None);
        };
        let Ok(record) = StripRecord::decode(&record_bytes) else {
            return Ok(None);
        };
        let body = serialize(block);
        // The record's filled hash pins every byte outside the spans, and its
        // txids must reproduce the merkle root: this is the block the record
        // describes, so writing it over the stripped bytes changes only the
        // spans.
        if StoredBlock::from_bytes(body.clone(), Some(record.clone()), &hash).is_err()
            || record.txs.iter().any(|t| {
                block.txdata.get(t.tx_index as usize).map(|tx| tx.compute_txid()) != Some(t.txid)
            })
        {
            return Ok(None);
        }

        let _accept = self.accept_lock.lock();
        let mut flat_files = self.flat_files.lock();
        let Some(entry) = self.store.get_block_index(&hash) else {
            return Ok(None);
        };
        if !matches!(entry.status, BlockStatus::DataStored | BlockStatus::Valid)
            || entry.height != height
            || self.store.get_opreturn_strip(&hash)?.as_deref() != Some(record_bytes.as_slice())
        {
            return Ok(None);
        }
        let pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        // The length prefix of the stored record: the copy must fill exactly
        // the space the stripped one takes.
        match flat_files.read_block(&pos) {
            Ok(stored) if stored.len() == body.len() => {}
            _ => return Ok(None),
        }
        let offset = u64::from(pos.data_pos) + 8;
        let mut encoded = body;
        crate::storage::flatfile::xor_in_place(&mut encoded, &flat_files.xor_key(), offset);
        let path = flat_files.blocks_dir().join(format!("blk{:05}.dat", pos.file_number));
        // A write that fails part way leaves the same block's bytes, partly
        // intact, under the record: readers still zero-fill the spans.
        let io = |e: std::io::Error| super::ChainError::FlatFile(format!("restoring {hash} in place: {e}"));
        let file = OpenOptions::new().write(true).open(&path).map_err(io)?;
        std::os::unix::fs::FileExt::write_all_at(&file, &encoded, offset).map_err(io)?;
        // The bytes are durable before the record goes. A crash between the
        // two leaves a full copy under a record, which reads as the filled
        // form; the next restore finishes it.
        file.sync_data().map_err(io)?;
        drop(flat_files);
        self.store.write_batch(StoreBatch {
            opreturn_strip_removes: vec![hash],
            ..Default::default()
        })?;
        self.flush_durable()?;
        self.forget_strip_summary();
        // Readable data where there was none can unblock a reorg that failed
        // on it.
        self.blocks_indexed.fetch_add(1, Ordering::AcqRel);
        tracing::info!(%hash, height, "Restored an OP_RETURN-stripped block in place from a peer-supplied copy");
        Ok(Some(super::BlockDataRepair::Repaired { height }))
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

/// The strip worker (plan §2.6): a pass, then another straight away while the
/// last stopped at its block limit, else a wait of up to a minute that ends
/// early when the tip moves. Runs until `stop`. Spawn it on a thread of its
/// own; every pass is blocking I/O.
pub fn run_strip_worker(chain: std::sync::Arc<ChainState>, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    const PASS_BLOCKS: u32 = 1000;
    const IDLE: std::time::Duration = std::time::Duration::from_secs(60);
    const POLL: std::time::Duration = std::time::Duration::from_millis(500);
    while !stop.load(Ordering::Relaxed) {
        let more = match chain.strip_pass(PASS_BLOCKS, &stop) {
            Ok(report) => {
                if report.stripped > 0 {
                    tracing::info!(
                        examined = report.examined,
                        stripped = report.stripped,
                        "OP_RETURN strip pass"
                    );
                }
                report.more
            }
            Err(e) => {
                tracing::warn!(error = %e, "OP_RETURN strip pass failed; retrying after the idle wait");
                false
            }
        };
        if more {
            continue;
        }
        // The option is off and the last stripped block is restored: there
        // is nothing left to keep count of.
        if !chain.opreturn_prune_active() {
            break;
        }
        let tip = chain.tip_height();
        let started = std::time::Instant::now();
        while started.elapsed() < IDLE && !stop.load(Ordering::Relaxed) && chain.tip_height() == tip {
            std::thread::sleep(POLL);
        }
    }
    *chain.strip.worker.lock() = WorkerStatus::Off;
}
