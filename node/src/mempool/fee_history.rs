//! Fee history from the chain: each recent block's hurdle, and the analog
//! window estimate read from them (fee plan F3).
//!
//! A block's **hurdle** ([`BlockFeeProfile::hurdle`]) is the weight-weighted
//! 10th percentile of its transactions' feerates, at or above min relay:
//! roughly what a transaction had to pay to get into that block. The store
//! keeps the hurdle of each of the last [`FEE_HISTORY_BLOCKS`] blocks of the
//! active chain in memory and saves it to [`FEE_HISTORY_FILE`] every
//! [`SAVE_EVERY_BLOCKS`] blocks and at shutdown. A start loads the file and
//! reads from block and undo data only what the file lacks, newest block
//! first. The file is what lets a pruned node, which keeps only a few
//! hundred blocks, build a full history: it gathers it live, across
//! restarts, from the blocks it connects.
//!
//! ## The estimate: analog windows
//!
//! The method is rbitcoin's (`docs/mempool-fee-estimation.md` in
//! reardencode/rbitcoin), reimplemented here from that description. For a
//! target of N blocks, every run of N consecutive hurdle blocks is a
//! **window**. Its **outcome** is the lowest hurdle inside it: a transaction
//! paying that much would have beaten at least one block's hurdle within N
//! blocks. Its **before-level** is the median hurdle of the
//! `L = clamp(N/4, 3, 144)` blocks just before it.
//!
//! The estimate keeps only the windows whose before-level is within ×1.25 of
//! the current before-level (and at least the 200 nearest), and takes a high
//! quantile of their outcomes. A spike earlier in the history therefore
//! does not raise the answer in a calm market, and a spike in progress is
//! answered from the past windows that started inside spikes. A plain
//! quantile over every window, which is the fallback until a target has
//! [`ANALOG_READY_WINDOWS`] windows, lets one spike steer every estimate
//! until it ages out.
//!
//! Blocks with no hurdle (coinbase-only, or every transaction under min
//! relay) are not observations: windows are taken over the blocks that
//! have one.
//!
//! ## Keeping it on the active chain
//!
//! The store is reconciled against the chain rather than trusting events:
//! [`HurdleHistory::sync`] walks back from the active tip, by parent hash,
//! to the newest row's height, then down both together until a row's hash
//! matches the chain's; every row above that point is dropped and the
//! walked blocks are added. A history loaded from the file after a reorg
//! while the node was down is trimmed the same way. A connect, a reorg, an IBD catch-up that emitted no
//! events, or a missed event all end the same way. Chain events only wake
//! the task sooner.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::BlockHash;
use bitcoin::hashes::{Hash, sha256d};
use parking_lot::RwLock;

use crate::chain::state::ChainState;
use crate::mining::fee_profile::BlockFeeProfile;

/// Blocks of history kept: enough for [`ANALOG_READY_WINDOWS`] windows at
/// the longest target, `2000 + L + N − 1 = 3151` at N = 1008 (L = 144), with
/// a margin for blocks that carry no hurdle.
pub const FEE_HISTORY_BLOCKS: usize = 3_200;

/// Windows a target needs before it answers from analog windows. Below
/// this it answers a plain quantile over the windows it has.
pub const ANALOG_READY_WINDOWS: usize = 2_000;

/// Analog band: a window's before-level within this factor of now's.
const ANALOG_BAND: f64 = 1.25;

/// At least this many windows are kept, the nearest by before-level, when
/// the band holds fewer.
const ANALOG_MIN_NEIGHBORS: usize = 200;

/// The longest target answered.
pub const MAX_TARGET: u32 = 1_008;

/// Targets the table is computed at. A target between two of them answers
/// the nearer one below it, which is the higher rate.
const LADDER: [u32; 29] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 18, 21, 24, 30, 36, 48, 60, 72, 96, 120, 144, 216, 288,
    432, 504, 720, 1008,
];

/// Quantiles of the selected outcomes. One block is answered at 99.9%,
/// the rest at 95% (economical) or 99% (conservative).
fn quantile(target: u32, conservative: bool) -> f64 {
    match (target, conservative) {
        (1, _) => 0.999,
        (_, false) => 0.95,
        (_, true) => 0.99,
    }
}

/// How a target's estimate was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistorySource {
    /// Analog windows: the target had [`ANALOG_READY_WINDOWS`] windows.
    Analog,
    /// A plain quantile over every window: the store is still filling.
    Plain,
}

/// One target's estimate, in sat/kvB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryEstimate {
    pub economical: u64,
    pub conservative: u64,
    pub source: HistorySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    height: u32,
    hash: BlockHash,
    hurdle: Option<u64>,
}

/// A block that cannot be priced: its data or undo data is not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable;

/// What the store reads from the chain. [`ChainState`] in the node; a fake
/// in tests.
pub trait HurdleSource {
    /// No history is gathered while this is true.
    fn in_initial_block_download(&self) -> bool;
    /// The active tip.
    fn tip(&self) -> (BlockHash, u32);
    /// The parent of `hash`, from the block index.
    fn parent(&self, hash: &BlockHash) -> Option<BlockHash>;
    /// The block's hurdle, `Ok(None)` for a block with no transaction at or
    /// above min relay, and [`Unreadable`] when the block or its undo data is
    /// not stored (pruned, or below an AssumeUTXO snapshot).
    fn hurdle(&self, hash: &BlockHash, min_relay_sat_per_kvb: u64) -> Result<Option<u64>, Unreadable>;
}

/// The per-block hurdle store and the estimates read from it.
pub struct HurdleHistory {
    /// Contiguous rows of the active chain, oldest first.
    rows: VecDeque<Row>,
    /// The estimate at each [`LADDER`] target, or `None` when the store has
    /// no complete window for it. Recomputed after the rows change.
    table: [Option<HistoryEstimate>; LADDER.len()],
    /// The backfill met a block it cannot read; it stops until the rows are
    /// replaced.
    backfill_blocked: bool,
    capacity: usize,
}

impl Default for HurdleHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl HurdleHistory {
    pub fn new() -> Self {
        Self::with_capacity(FEE_HISTORY_BLOCKS)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self { rows: VecDeque::new(), table: [None; LADDER.len()], backfill_blocked: false, capacity }
    }

    /// Rows held.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The `(height, hash)` of the newest row.
    pub fn newest(&self) -> Option<(u32, BlockHash)> {
        self.rows.back().map(|r| (r.height, r.hash))
    }

    /// The estimate for `target` blocks (1 to [`MAX_TARGET`]; larger
    /// targets answer 1008), or `None` when no window covers it yet.
    pub fn estimate(&self, target: u32) -> Option<HistoryEstimate> {
        let target = target.clamp(1, MAX_TARGET);
        let idx = LADDER.iter().rposition(|&t| t <= target)?;
        self.table[idx]
    }

    /// Bring the rows in line with the active chain, then read up to
    /// `backfill_budget` older blocks below the oldest row. Returns `true`
    /// when there is more backfill to do.
    pub fn sync(
        &mut self,
        chain: &impl HurdleSource,
        min_relay_sat_per_kvb: u64,
        backfill_budget: usize,
    ) -> bool {
        if chain.in_initial_block_download() {
            return false;
        }
        let mut changed = self.sync_top(chain, min_relay_sat_per_kvb);
        let mut read = 0;
        while read < backfill_budget && self.wants_backfill() {
            let oldest = *self.rows.front().expect("wants_backfill implies a row");
            let Some(parent) = chain.parent(&oldest.hash) else {
                self.backfill_blocked = true;
                break;
            };
            match chain.hurdle(&parent, min_relay_sat_per_kvb) {
                Ok(hurdle) => {
                    self.rows.push_front(Row { height: oldest.height - 1, hash: parent, hurdle });
                    changed = true;
                    read += 1;
                }
                Err(Unreadable) => {
                    self.backfill_blocked = true;
                    break;
                }
            }
        }
        if changed {
            self.recompute();
        }
        self.wants_backfill()
    }

    fn wants_backfill(&self) -> bool {
        !self.backfill_blocked
            && self.rows.len() < self.capacity
            && self.rows.front().is_some_and(|r| r.height > 0)
    }

    /// Bring the top of the store onto the active chain: walk back from the
    /// tip by parent hash to the newest row's height, then down the rows and
    /// the chain together until a row's hash is the chain's, dropping every
    /// row passed on the way; then add the walked blocks. Returns whether
    /// the rows changed.
    fn sync_top(&mut self, chain: &impl HurdleSource, min_relay: u64) -> bool {
        let (mut hash, mut height) = chain.tip();
        // Rows wholly older than the history's span: start again at the
        // tip and let the backfill read downward.
        if self.rows.back().is_some_and(|r| r.height as usize + self.capacity <= height as usize) {
            self.rows.clear();
            self.backfill_blocked = false;
        }
        let mut walked: Vec<(u32, BlockHash)> = Vec::new();
        loop {
            while self.rows.back().is_some_and(|r| r.height > height) {
                self.rows.pop_back();
            }
            // A row at this height on another branch is popped by the
            // line above once the walk steps below it.
            if self.rows.back().is_some_and(|r| r.height == height && r.hash == hash) {
                break;
            }
            walked.push((height, hash));
            // An empty store takes the tip alone; the backfill reads on.
            if self.rows.is_empty() || height == 0 {
                break;
            }
            match chain.parent(&hash) {
                Some(p) => {
                    hash = p;
                    height -= 1;
                }
                None => {
                    self.rows.clear();
                    break;
                }
            }
        }
        if self.rows.is_empty() {
            walked.truncate(1);
            self.backfill_blocked = false;
        }
        if walked.is_empty() {
            return false;
        }
        for &(h, hash) in walked.iter().rev() {
            // A block at the top that cannot be read (it always can, short
            // of corruption) counts as one with no hurdle.
            let hurdle = chain.hurdle(&hash, min_relay).unwrap_or(None);
            self.rows.push_back(Row { height: h, hash, hurdle });
        }
        while self.rows.len() > self.capacity {
            self.rows.pop_front();
        }
        true
    }

    fn recompute(&mut self) {
        let hurdles: Vec<u64> = self.rows.iter().filter_map(|r| r.hurdle).collect();
        let mut table = [None; LADDER.len()];
        for (i, &target) in LADDER.iter().enumerate() {
            table[i] = estimate_from_hurdles(&hurdles, target);
        }
        clamp_monotone(&mut table);
        self.table = table;
    }
}

/// A longer target never answers more than a shorter one: each entry is
/// lowered to the one before it.
fn clamp_monotone(table: &mut [Option<HistoryEstimate>]) {
    let mut ceiling: Option<(u64, u64)> = None;
    for e in table.iter_mut().flatten() {
        if let Some((econ, cons)) = ceiling {
            e.economical = e.economical.min(econ);
            e.conservative = e.conservative.min(cons);
        }
        ceiling = Some((e.economical, e.conservative));
    }
}

/// The estimate for `target` from hurdles in chain order, oldest first:
/// analog windows once there are [`ANALOG_READY_WINDOWS`] of them, a plain
/// quantile over every window before that, `None` with no complete window.
pub fn estimate_from_hurdles(hurdles: &[u64], target: u32) -> Option<HistoryEstimate> {
    let n = target.max(1) as usize;
    let l = lookback(target);
    let windows = hurdles.len().checked_sub(l + n)? + 1;
    let outcomes = window_outcomes(hurdles, l, n);
    debug_assert_eq!(outcomes.len(), windows);
    let (mut selected, source) = if windows >= ANALOG_READY_WINDOWS {
        let levels = window_levels(hurdles, l, windows);
        let now = median(&hurdles[hurdles.len() - l..]);
        (select_analogs(&levels, &outcomes, now), HistorySource::Analog)
    } else {
        (outcomes, HistorySource::Plain)
    };
    selected.sort_unstable();
    let economical = log_quantile(&selected, quantile(target, false));
    let conservative = log_quantile(&selected, quantile(target, true));
    Some(HistoryEstimate { economical, conservative, source })
}

/// `clamp(N/4, 3, 144)` blocks of lookback.
fn lookback(target: u32) -> usize {
    (target as usize / 4).clamp(3, 144)
}

/// Each window's outcome: the lowest hurdle in `hurdles[i..i+n]` for every
/// window start `i` from `l`, with a monotone deque (O(len)).
fn window_outcomes(hurdles: &[u64], l: usize, n: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(hurdles.len().saturating_sub(l + n - 1));
    let mut dq: VecDeque<usize> = VecDeque::new();
    for (j, &h) in hurdles.iter().enumerate().skip(l) {
        while dq.back().is_some_and(|&k| hurdles[k] >= h) {
            dq.pop_back();
        }
        dq.push_back(j);
        // Window [j+1-n, j]; it starts at `l` or later.
        if j + 1 >= l + n {
            let start = j + 1 - n;
            while dq.front().is_some_and(|&k| k < start) {
                dq.pop_front();
            }
            out.push(hurdles[*dq.front().expect("j is in the deque")]);
        }
    }
    out
}

/// Each window's before-level: the median of the `l` hurdles before it.
fn window_levels(hurdles: &[u64], l: usize, windows: usize) -> Vec<u64> {
    let mut buf = Vec::with_capacity(l);
    (0..windows)
        .map(|w| {
            buf.clear();
            buf.extend_from_slice(&hurdles[w..w + l]);
            median_in_place(&mut buf)
        })
        .collect()
}

fn median(xs: &[u64]) -> u64 {
    let mut v = xs.to_vec();
    median_in_place(&mut v)
}

/// The lower median.
fn median_in_place(v: &mut [u64]) -> u64 {
    let mid = (v.len() - 1) / 2;
    *v.select_nth_unstable(mid).1
}

/// The outcomes of the windows whose before-level is within
/// [`ANALOG_BAND`] of `now`, or of the [`ANALOG_MIN_NEIGHBORS`] nearest
/// when the band holds fewer.
fn select_analogs(levels: &[u64], outcomes: &[u64], now: u64) -> Vec<u64> {
    // Distance in log space; +1 keeps a zero level finite.
    let ln_now = ((now + 1) as f64).ln();
    let mut by_distance: Vec<(f64, u64)> = levels
        .iter()
        .zip(outcomes)
        .map(|(&lvl, &out)| ((((lvl + 1) as f64).ln() - ln_now).abs(), out))
        .collect();
    let band = ANALOG_BAND.ln();
    let in_band = by_distance.iter().filter(|(d, _)| *d <= band).count();
    if in_band >= ANALOG_MIN_NEIGHBORS {
        return by_distance.into_iter().filter(|(d, _)| *d <= band).map(|(_, o)| o).collect();
    }
    let k = ANALOG_MIN_NEIGHBORS.min(by_distance.len());
    by_distance.select_nth_unstable_by(k - 1, |a, b| a.0.total_cmp(&b.0));
    by_distance.truncate(k);
    by_distance.into_iter().map(|(_, o)| o).collect()
}

/// Quantile `q` of sorted `v`, interpolated in log-rate between the two
/// nearest values and rounded to the nearest sat/kvB. Equal neighbours
/// answer that value; a zero neighbour interpolates linearly.
fn log_quantile(v: &[u64], q: f64) -> u64 {
    let pos = q * (v.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    let (a, b) = (v[lo], v[hi]);
    if a == b {
        return a;
    }
    let frac = pos - lo as f64;
    let r = if a == 0 {
        a as f64 + frac * (b - a) as f64
    } else {
        ((a as f64).ln() + frac * ((b as f64).ln() - (a as f64).ln())).exp()
    };
    r.round() as u64
}

impl HurdleSource for ChainState {
    fn in_initial_block_download(&self) -> bool {
        self.is_initial_block_download()
    }

    fn tip(&self) -> (BlockHash, u32) {
        self.tip_snapshot()
    }

    fn parent(&self, hash: &BlockHash) -> Option<BlockHash> {
        let entry = self.get_block_index(hash)?;
        (entry.height > 0).then_some(entry.header.prev_blockhash)
    }

    fn hurdle(&self, hash: &BlockHash, min_relay: u64) -> Result<Option<u64>, Unreadable> {
        let block = self.get_stored_block(hash).ok_or(Unreadable)?.block;
        match self.read_undo(hash).map_err(|_| Unreadable)? {
            Some(undo) => {
                let profile = BlockFeeProfile::from_undo(&block, &undo).map_err(|_| Unreadable)?;
                Ok(profile.hurdle(min_relay))
            }
            // Only a block with nothing to spend has no undo row once
            // connected: the genesis block, or a coinbase-only block.
            None if block.txdata.len() <= 1 => Ok(None),
            None => Err(Unreadable),
        }
    }
}

/// The history file, under the network data directory.
pub const FEE_HISTORY_FILE: &str = "fees/fee_history.dat";

/// The file is saved after this many new blocks, and at shutdown.
pub const SAVE_EVERY_BLOCKS: u32 = 144;

const FILE_MAGIC: &[u8; 4] = b"SFHH";
const FILE_VERSION: u32 = 1;
/// A hurdle of `None` on disk.
const NO_HURDLE: u64 = u64::MAX;
/// height (4) + hash (32) + hurdle (8).
const ROW_BYTES: usize = 44;

impl HurdleHistory {
    /// The file's bytes: magic, version, the network's P2P magic, the row
    /// count, the rows oldest first, then the hash256 of all of that.
    pub fn serialize(&self, network_magic: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.rows.len() * ROW_BYTES + 32);
        out.extend_from_slice(FILE_MAGIC);
        out.extend_from_slice(&FILE_VERSION.to_le_bytes());
        out.extend_from_slice(&network_magic);
        out.extend_from_slice(&(self.rows.len() as u32).to_le_bytes());
        for r in &self.rows {
            out.extend_from_slice(&r.height.to_le_bytes());
            out.extend_from_slice(r.hash.as_byte_array());
            out.extend_from_slice(&r.hurdle.unwrap_or(NO_HURDLE).to_le_bytes());
        }
        let check = sha256d::Hash::hash(&out);
        out.extend_from_slice(check.as_byte_array());
        out
    }

    /// Replace the rows with the ones in `bytes`. A file for another
    /// network, another version, with a bad checksum, or whose rows are
    /// not consecutive heights is refused, and the store is left empty.
    /// The rows are not checked against the chain here: the first
    /// [`Self::sync`] drops any above the newest one still on it.
    pub fn load_bytes(&mut self, bytes: &[u8], network_magic: [u8; 4]) -> Result<usize, String> {
        self.rows.clear();
        self.backfill_blocked = false;
        let rows = parse(bytes, network_magic)?;
        let skip = rows.len().saturating_sub(self.capacity);
        self.rows.extend(rows.into_iter().skip(skip));
        self.recompute();
        Ok(self.rows.len())
    }

    /// [`Self::load_bytes`] from `path`. A missing file is an empty store.
    pub fn load(&mut self, path: &Path, network_magic: [u8; 4]) -> Result<usize, String> {
        match std::fs::read(path) {
            Ok(bytes) => self.load_bytes(&bytes, network_magic),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.rows.clear();
                Ok(0)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Write the file through a temporary file, an fsync and a rename.
    pub fn save(&self, path: &Path, network_magic: [u8; 4]) -> std::io::Result<()> {
        use std::io::Write as _;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("dat.new");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&self.serialize(network_magic))?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }
}

fn parse(bytes: &[u8], network_magic: [u8; 4]) -> Result<Vec<Row>, String> {
    let take = |at: usize, n: usize| bytes.get(at..at + n).ok_or_else(|| "truncated".to_string());
    if take(0, 4)? != FILE_MAGIC {
        return Err("not a satd fee history file".into());
    }
    let version = u32::from_le_bytes(take(4, 4)?.try_into().unwrap());
    if version != FILE_VERSION {
        return Err(format!("unsupported version {version}"));
    }
    if take(8, 4)? != network_magic {
        return Err("written for another network".into());
    }
    let count = u32::from_le_bytes(take(12, 4)?.try_into().unwrap()) as usize;
    let body = 16 + count.checked_mul(ROW_BYTES).ok_or("row count overflows")?;
    if bytes.len() != body + 32 {
        return Err(format!("{} bytes for {count} rows", bytes.len()));
    }
    if sha256d::Hash::hash(&bytes[..body]).as_byte_array()[..] != bytes[body..] {
        return Err("checksum mismatch".into());
    }
    let mut rows: Vec<Row> = Vec::with_capacity(count);
    for i in 0..count {
        let at = 16 + i * ROW_BYTES;
        let height = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let hash = BlockHash::from_byte_array(bytes[at + 4..at + 36].try_into().unwrap());
        let raw = u64::from_le_bytes(bytes[at + 36..at + 44].try_into().unwrap());
        if let Some(prev) = rows.last()
            && height != prev.height.wrapping_add(1)
        {
            return Err("non-consecutive heights".into());
        }
        rows.push(Row { height, hash, hurdle: (raw != NO_HURDLE).then_some(raw) });
    }
    Ok(rows)
}

/// Whether the task saves the file after a pass: `newest` is the newest
/// row now, `saved_at` the newest at the last save. Every
/// [`SAVE_EVERY_BLOCKS`] new blocks, after a reorg below the saved tip, and
/// when a backfill has just finished; never while one still runs.
fn save_due(newest: Option<u32>, saved_at: Option<u32>, was_backfilling: bool, more: bool) -> bool {
    if more {
        return false;
    }
    match (newest, saved_at) {
        (Some(n), Some(s)) => n >= s + SAVE_EVERY_BLOCKS || n < s || was_backfilling,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Blocks the background task reads per pass before it lets go of the
/// lock and checks for a new tip.
const BACKFILL_CHUNK: usize = 32;

/// How often the task reconciles with no chain event to wake it.
const SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// Keep `history` on the active chain for the life of the node: a pass on
/// every chain event and every [`SYNC_INTERVAL`], and back-to-back passes
/// while the backfill has blocks to read. Each pass runs on the blocking
/// pool.
pub fn spawn_fee_history(
    chain_state: Arc<ChainState>,
    history: Arc<RwLock<HurdleHistory>>,
    min_relay: impl Fn() -> u64 + Send + Sync + 'static,
    save_to: Option<(std::path::PathBuf, [u8; 4])>,
    mut chain_rx: Option<tokio::sync::broadcast::Receiver<crate::chain::events::ChainEvent>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let min_relay = Arc::new(min_relay);
    tokio::spawn(async move {
        // The rebuild clock starts at the first pass that holds a row:
        // time spent waiting out IBD is not rebuild time.
        let mut started: Option<std::time::Instant> = None;
        let mut logged_full = false;
        // The newest height saved, and whether the backfill was running at
        // the last pass: the file is saved every `SAVE_EVERY_BLOCKS` new
        // blocks, and once when a backfill finishes.
        let mut saved_at: Option<u32> = history.read().newest().map(|(h, _)| h);
        let mut was_backfilling = false;
        loop {
            let (cs, hist, mr) = (chain_state.clone(), history.clone(), min_relay.clone());
            let pass = tokio::task::spawn_blocking(move || {
                // Read the blocks outside the lock, then apply: a reader
                // (an RPC) never waits on block I/O. The pass works on a
                // copy of the rows and swaps it in.
                let mut work = hist.read().clone_rows();
                let more = work.sync(&*cs, mr(), BACKFILL_CHUNK);
                let len = work.len();
                *hist.write() = work;
                (more, len)
            })
            .await;
            let Ok((more, len)) = pass else { return };
            let newest = history.read().newest().map(|(h, _)| h);
            let due = save_due(newest, saved_at, was_backfilling, more);
            was_backfilling = more;
            if due && let Some((path, magic)) = save_to.clone() {
                let hist = history.clone();
                let saved = tokio::task::spawn_blocking(move || hist.read().save(&path, magic)).await;
                match saved {
                    Ok(Ok(())) => saved_at = newest,
                    Ok(Err(e)) => tracing::warn!(target: "fees", error = %e, "cannot save fee history"),
                    Err(_) => return,
                }
            }
            if len > 0 && started.is_none() {
                started = Some(std::time::Instant::now());
            }
            if let (false, false, Some(t)) = (more, logged_full, started) {
                logged_full = true;
                tracing::info!(
                    target: "fees",
                    blocks = len,
                    elapsed_ms = t.elapsed().as_millis() as u64,
                    "fee history ready",
                );
            }
            if *shutdown.borrow() {
                return;
            }
            if more {
                tokio::task::yield_now().await;
                continue;
            }
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(SYNC_INTERVAL) => {}
                ev = async {
                    match chain_rx.as_mut() {
                        Some(rx) => rx.recv().await.map(|_| ()),
                        None => std::future::pending().await,
                    }
                } => {
                    if let Err(tokio::sync::broadcast::error::RecvError::Closed) = ev {
                        chain_rx = None;
                    }
                }
            }
        }
    })
}

impl HurdleHistory {
    /// A copy of the store for a pass to work on.
    fn clone_rows(&self) -> Self {
        Self {
            rows: self.rows.clone(),
            table: self.table,
            backfill_blocked: self.backfill_blocked,
            capacity: self.capacity,
        }
    }
}

#[cfg(test)]
#[path = "fee_history_tests.rs"]
mod tests;
