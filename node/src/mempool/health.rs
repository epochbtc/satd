//! Mempool health: Bitcoin Core 32's test of whether this node's mempool is
//! representative enough to price a fee estimate from.
//!
//! Over the last [`HEALTH_WINDOW_BLOCKS`] contiguous connected blocks, at
//! least [`REPRESENTATION_THRESHOLD`] of their non-coinbase weight must have
//! been in this mempool before the block arrived. The check is skipped (the
//! mempool counts as healthy) when those blocks together hold less than one
//! full block of weight. This follows Core v32.1
//! `src/policy/fees/mempool_estimator.cpp` (`AddMinedBlockStats`,
//! `GetMempoolHealth`), with the same constants, and persists the window in
//! the way Core persists `fees/mempool_policy_estimator.dat`: a version, the
//! rows, and the tip they end at, discarded on load unless they end at the
//! active tip.
//!
//! One addition: a block can be reported twice (the chain's own mempool
//! cleanup and the caller's), so a second report of the newest block, by
//! the same hash, adds the weight it removed instead of replacing the row.
//! The second call removes nothing, so the row keeps the first call's count.

use std::path::{Path, PathBuf};

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;

/// Core's `MEMPOOL_HEALTH_WINDOW_BLOCKS`.
pub const HEALTH_WINDOW_BLOCKS: usize = 6;
/// Core's `MEMPOOL_REPRESENTATION_THRESHOLD`.
pub const REPRESENTATION_THRESHOLD: f64 = 0.75;
/// Core's `MIN_REPRESENTATIVE_WINDOW_WEIGHT`: one full block
/// (`DEFAULT_BLOCK_MAX_WEIGHT`, which is `MAX_BLOCK_WEIGHT`).
pub const MIN_REPRESENTATIVE_WINDOW_WEIGHT: u64 = 4_000_000;

/// The window's file, under the network datadir.
pub const HEALTH_FILE: &str = "fees/mempool_health.dat";
/// File format version (Core's `CURRENT_MEMPOOL_ESTIMATOR_VERSION` is 1 too,
/// but the formats are satd's own and not interchangeable).
const FILE_VERSION: u32 = 1;
const FILE_MAGIC: &[u8; 4] = b"SFMH";

/// One connected block's numbers: Core's `MinedBlockStats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinedBlockStats {
    pub height: u64,
    /// Weight of the block's non-coinbase transactions.
    pub block_weight: u64,
    /// Weight of the transactions removed from this mempool for the block.
    pub mempool_txs_weight: u64,
}

/// Core's `MempoolHealth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolHealth {
    Healthy,
    InsufficientData,
    LowCoverage,
}

impl MempoolHealth {
    /// The `mempool_health` verdict string (a satd-only field).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::InsufficientData => "insufficient_data",
            Self::LowCoverage => "low_coverage",
        }
    }

    /// Core's `MempoolHealthError` text, or `None` when healthy.
    pub fn error(&self) -> Option<&'static str> {
        match self {
            Self::Healthy => None,
            Self::InsufficientData => Some("Not enough recent block data for fee rate estimation"),
            Self::LowCoverage => Some("Mempool is unreliable for fee rate estimation"),
        }
    }
}

/// The window of recent blocks the verdict is taken over.
#[derive(Debug, Default)]
pub struct HealthWindow {
    blocks: Vec<MinedBlockStats>,
    /// Hash of the newest row's block (Core's `m_mined_blocks_tip_hash`).
    tip_hash: Option<BlockHash>,
    path: Option<PathBuf>,
}

impl HealthWindow {
    /// Record a connected block. Core's `AddMinedBlockStats`: rows at or
    /// above `height` are stale (a reorg) and dropped, and a height gap
    /// clears the window.
    pub fn record(&mut self, hash: BlockHash, stats: MinedBlockStats) {
        if let Some(last) = self.blocks.last_mut()
            && last.height == stats.height
            && self.tip_hash == Some(hash)
        {
            // The same block reported again.
            last.mempool_txs_weight = last.mempool_txs_weight.saturating_add(stats.mempool_txs_weight);
            return;
        }
        self.blocks.retain(|b| b.height < stats.height);
        if let Some(last) = self.blocks.last()
            && last.height + 1 != stats.height
        {
            self.blocks.clear();
        }
        if self.blocks.len() == HEALTH_WINDOW_BLOCKS {
            self.blocks.remove(0);
        }
        self.blocks.push(stats);
        self.tip_hash = Some(hash);
    }

    /// Core's `MempoolLoadFailed`: the mempool did not load, so these rows
    /// describe a mempool this node no longer has.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.tip_hash = None;
    }

    /// Oldest first.
    pub fn blocks(&self) -> &[MinedBlockStats] {
        &self.blocks
    }

    /// Core's `GetMempoolHealth`.
    pub fn health(&self) -> MempoolHealth {
        if self.blocks.len() < HEALTH_WINDOW_BLOCKS {
            return MempoolHealth::InsufficientData;
        }
        let total_block: u64 = self.blocks.iter().map(|b| b.block_weight).sum();
        let total_removed: u64 = self.blocks.iter().map(|b| b.mempool_txs_weight).sum();
        if total_block < MIN_REPRESENTATIVE_WINDOW_WEIGHT {
            return MempoolHealth::Healthy;
        }
        if total_removed as f64 / total_block as f64 >= REPRESENTATION_THRESHOLD {
            MempoolHealth::Healthy
        } else {
            MempoolHealth::LowCoverage
        }
    }

    /// Bind the window to its file and read it, keeping the rows only if
    /// they are well formed and end at the active tip (`tip`), as Core's
    /// `Read` does. A missing, foreign or stale file leaves the window empty.
    pub fn open(&mut self, net_datadir: &Path, tip: (u64, BlockHash)) {
        let path = net_datadir.join(HEALTH_FILE);
        self.clear();
        match std::fs::read(&path) {
            Ok(bytes) => match parse(&bytes) {
                Ok((blocks, hash)) => {
                    let ends_at_tip = blocks.last().is_none_or(|b| b.height == tip.0 && hash == tip.1);
                    if ends_at_tip {
                        self.tip_hash = (!blocks.is_empty()).then_some(hash);
                        self.blocks = blocks;
                    } else {
                        tracing::warn!(
                            file = %path.display(),
                            "mempool health stats do not end at the active tip; ignoring them"
                        );
                    }
                }
                Err(reason) => {
                    tracing::warn!(file = %path.display(), %reason, "ignoring mempool health stats");
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(file = %path.display(), error = %e, "cannot read mempool health stats"),
        }
        self.path = Some(path);
    }

    /// The bytes [`Self::flush`] writes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 + 1 + self.blocks.len() * 24 + 32);
        out.extend_from_slice(FILE_MAGIC);
        out.extend_from_slice(&FILE_VERSION.to_le_bytes());
        out.push(self.blocks.len() as u8);
        for b in &self.blocks {
            out.extend_from_slice(&b.height.to_le_bytes());
            out.extend_from_slice(&b.mempool_txs_weight.to_le_bytes());
            out.extend_from_slice(&b.block_weight.to_le_bytes());
        }
        let hash = self.tip_hash.unwrap_or_else(BlockHash::all_zeros);
        out.extend_from_slice(hash.as_byte_array());
        out
    }

    /// The file path and contents to write, if the window is bound to one.
    /// Split from the write so the caller can do the I/O outside its lock.
    pub fn flush_job(&self) -> Option<(PathBuf, Vec<u8>)> {
        self.path.clone().map(|p| (p, self.serialize()))
    }
}

/// Write a [`HealthWindow::flush_job`] through a temporary file and a
/// rename. Failures are logged, not returned: the file is disposable.
pub fn write_flush_job(path: &Path, bytes: &[u8]) {
    let result = (|| -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("dat.new");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        tracing::warn!(file = %path.display(), error = %e, "cannot write mempool health stats");
    }
}

fn parse(bytes: &[u8]) -> Result<(Vec<MinedBlockStats>, BlockHash), String> {
    let take = |at: usize, n: usize| bytes.get(at..at + n).ok_or_else(|| "truncated".to_string());
    if take(0, 4)? != FILE_MAGIC {
        return Err("not a satd mempool health file".into());
    }
    let version = u32::from_le_bytes(take(4, 4)?.try_into().unwrap());
    if version != FILE_VERSION {
        return Err(format!("unsupported version {version}"));
    }
    let count = take(8, 1)?[0] as usize;
    if count > HEALTH_WINDOW_BLOCKS {
        return Err(format!("{count} rows, more than {HEALTH_WINDOW_BLOCKS}"));
    }
    let u64_at = |at: usize| -> Result<u64, String> {
        Ok(u64::from_le_bytes(take(at, 8)?.try_into().unwrap()))
    };
    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let at = 9 + i * 24;
        blocks.push(MinedBlockStats {
            height: u64_at(at)?,
            mempool_txs_weight: u64_at(at + 8)?,
            block_weight: u64_at(at + 16)?,
        });
    }
    for pair in blocks.windows(2) {
        if pair[1].height != pair[0].height.saturating_add(1) {
            return Err("non-consecutive heights".into());
        }
    }
    let at = 9 + count * 24;
    let hash = BlockHash::from_byte_array(take(at, 32)?.try_into().unwrap());
    if bytes.len() != at + 32 {
        return Err("trailing bytes".into());
    }
    Ok((blocks, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEIGHT: u64 = MIN_REPRESENTATIVE_WINDOW_WEIGHT / 2;

    fn hash(n: u64) -> BlockHash {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_le_bytes());
        BlockHash::from_byte_array(b)
    }

    /// Core's test helper `AddRemovedBlock`: record a block and advance.
    fn add(w: &mut HealthWindow, removed: u64, block: u64, height: &mut u64) {
        w.record(hash(*height), MinedBlockStats { height: *height, block_weight: block, mempool_txs_weight: removed });
        *height += 1;
    }

    fn healthy(w: &HealthWindow) -> bool {
        w.health() == MempoolHealth::Healthy
    }

    /// Core v32.1 `src/test/mempool_fee_estimator_tests.cpp`, the
    /// `MempoolFeeRateEstimator` case: every health verdict it asserts, in
    /// its order, with its weights.
    #[test]
    fn health_gate_reproduces_cores_verdicts() {
        let mut w = HealthWindow::default();
        assert_eq!(w.health(), MempoolHealth::InsufficientData);

        // A low-activity window is healthy whatever its coverage.
        {
            let mut custom = HealthWindow::default();
            let mut h = 100;
            for _ in 1..HEALTH_WINDOW_BLOCKS {
                add(&mut custom, 0, 0, &mut h);
                assert!(!healthy(&custom));
            }
            add(&mut custom, 500, 1000, &mut h);
            assert!(healthy(&custom), "below one block of activity the ratio is skipped");
        }

        let mut height = 100;
        for count in 1..=HEALTH_WINDOW_BLOCKS {
            add(&mut w, WEIGHT, WEIGHT, &mut height);
            if count < HEALTH_WINDOW_BLOCKS {
                assert!(!healthy(&w), "{count} blocks");
            }
        }
        assert!(healthy(&w), "coverage 100%");
        add(&mut w, WEIGHT / 2, WEIGHT, &mut height);
        assert!(healthy(&w), "coverage ~92%");
        add(&mut w, 0, 0, &mut height);
        assert!(healthy(&w), "coverage 90%");
        add(&mut w, WEIGHT / 2, WEIGHT, &mut height);
        assert!(healthy(&w), "coverage 80%");
        add(&mut w, WEIGHT / 2, WEIGHT, &mut height);
        assert_eq!(w.health(), MempoolHealth::LowCoverage, "coverage 70%");
        for count in 1..=3 {
            add(&mut w, WEIGHT, WEIGHT, &mut height);
            if count < 3 {
                assert!(!healthy(&w));
            }
        }
        assert!(healthy(&w), "coverage 80%");

        // Replacing the tip block keeps a full window.
        height -= 1;
        add(&mut w, WEIGHT, WEIGHT, &mut height);
        assert!(healthy(&w));

        // Reorging out two blocks leaves too few rows until the chain catches up.
        height -= 2;
        add(&mut w, WEIGHT, WEIGHT, &mut height);
        assert_eq!(w.health(), MempoolHealth::InsufficientData);
        add(&mut w, WEIGHT, WEIGHT, &mut height);
        assert!(healthy(&w));

        // A forward gap resets the window.
        height += 3;
        add(&mut w, WEIGHT, WEIGHT, &mut height);
        assert!(!healthy(&w));
        for i in 1..HEALTH_WINDOW_BLOCKS {
            add(&mut w, WEIGHT, WEIGHT, &mut height);
            if i < HEALTH_WINDOW_BLOCKS - 1 {
                assert!(!healthy(&w));
            }
        }
        assert!(healthy(&w));
    }

    #[test]
    fn a_block_reported_twice_keeps_its_coverage() {
        let mut w = HealthWindow::default();
        let stats = MinedBlockStats { height: 7, block_weight: 1000, mempool_txs_weight: 900 };
        w.record(hash(7), stats);
        // The second cleanup of the same block finds nothing left to remove.
        w.record(hash(7), MinedBlockStats { mempool_txs_weight: 0, ..stats });
        assert_eq!(w.blocks(), &[stats]);
        // A different block at that height is a reorg and replaces the row.
        w.record(hash(70), MinedBlockStats { mempool_txs_weight: 0, ..stats });
        assert_eq!(w.blocks()[0].mempool_txs_weight, 0);
    }

    #[test]
    fn the_window_persists_and_is_kept_only_at_the_active_tip() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = HealthWindow::default();
        w.open(dir.path(), (0, BlockHash::all_zeros()));
        let mut height = 10;
        for _ in 0..HEALTH_WINDOW_BLOCKS {
            add(&mut w, WEIGHT, WEIGHT, &mut height);
        }
        let (path, bytes) = w.flush_job().unwrap();
        write_flush_job(&path, &bytes);
        assert!(dir.path().join(HEALTH_FILE).exists());

        let tip = (height - 1, hash(height - 1));
        let mut back = HealthWindow::default();
        back.open(dir.path(), tip);
        assert_eq!(back.blocks(), w.blocks());
        assert!(healthy(&back));

        // The chain moved on without these stats (an unclean shutdown): ignored.
        let mut stale = HealthWindow::default();
        stale.open(dir.path(), (height, hash(height)));
        assert!(stale.blocks().is_empty());
        let mut wrong_hash = HealthWindow::default();
        wrong_hash.open(dir.path(), (tip.0, hash(999)));
        assert!(wrong_hash.blocks().is_empty());

        // A foreign or torn file: ignored.
        std::fs::write(dir.path().join(HEALTH_FILE), b"garbage").unwrap();
        let mut foreign = HealthWindow::default();
        foreign.open(dir.path(), tip);
        assert!(foreign.blocks().is_empty());
        std::fs::write(dir.path().join(HEALTH_FILE), &bytes[..bytes.len() - 1]).unwrap();
        let mut torn = HealthWindow::default();
        torn.open(dir.path(), tip);
        assert!(torn.blocks().is_empty());
    }

    #[test]
    fn health_errors_are_cores_text() {
        assert_eq!(MempoolHealth::Healthy.error(), None);
        assert_eq!(
            MempoolHealth::InsufficientData.error(),
            Some("Not enough recent block data for fee rate estimation")
        );
        assert_eq!(
            MempoolHealth::LowCoverage.error(),
            Some("Mempool is unreliable for fee rate estimation")
        );
    }
}
