//! Persistent mempool history — periodic snapshots of size, fee
//! extremes, and the fee-rate histogram.
//!
//! Modelled on `chain::reorg_log`. A tokio task in `main.rs` calls
//! `record_if_changed` every N seconds; the resulting `MempoolSnapshot`
//! goes into a `VecDeque` capped at `capacity` (default 256) and is
//! appended to `$net_datadir/mempool_history.log` as JSONL. On startup
//! the ring is seeded from the file so operators can query recent
//! history across restarts.
//!
//! Deliberately loose semantics: we dedupe back-to-back identical
//! snapshots (same txid set + same weight) to avoid writing a boring
//! JSONL line every 10 s while the mempool is idle.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use bitcoin::Txid;
use serde::{Deserialize, Serialize};

use crate::mempool::estimate::HistogramBucket;
use crate::mempool::pool::{Mempool, MempoolEntry};

/// Default ring cap — ~40 min at 10 s cadence, covers the doc's
/// `--minutes=60` target with room to spare while staying tiny
/// (256 × ~300 B ≈ 75 KiB).
pub const DEFAULT_RING_CAPACITY: usize = 256;

/// One persisted mempool snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolSnapshot {
    pub ts_unix_secs: u64,
    pub size: usize,
    pub bytes: usize,
    pub min_fee_rate_sat_per_kvb: u64,
    pub max_fee_rate_sat_per_kvb: u64,
    pub histogram: Vec<HistogramBucket>,
}

/// Dedupe signature for `record_if_changed`. Captures everything
/// semantically meaningful about a snapshot *except* the timestamp,
/// so a snapshot where the histogram shifted but size/bytes/extremes
/// stayed the same still gets recorded.
#[derive(Clone, PartialEq, Eq)]
struct SnapshotSig {
    size: usize,
    bytes: usize,
    min_fee_rate_sat_per_kvb: u64,
    max_fee_rate_sat_per_kvb: u64,
    /// Flattened histogram buckets: (feerate_sat_per_kvb, weight). A
    /// Vec of tuples is Eq without needing to derive traits on the
    /// public `HistogramBucket` type.
    histogram: Vec<(u64, u64)>,
}

impl SnapshotSig {
    fn from(snapshot: &MempoolSnapshot) -> Self {
        Self {
            size: snapshot.size,
            bytes: snapshot.bytes,
            min_fee_rate_sat_per_kvb: snapshot.min_fee_rate_sat_per_kvb,
            max_fee_rate_sat_per_kvb: snapshot.max_fee_rate_sat_per_kvb,
            histogram: snapshot
                .histogram
                .iter()
                .map(|b| (b.feerate_sat_per_kvb, b.weight))
                .collect(),
        }
    }
}

/// In-process mempool history ring + append-only JSONL log.
pub struct MempoolHistory {
    path: PathBuf,
    ring: Mutex<VecDeque<MempoolSnapshot>>,
    capacity: usize,
    /// Full-content signature of the last-written snapshot (minus the
    /// timestamp) — used to skip writing an identical snapshot.
    last_sig: Mutex<Option<SnapshotSig>>,
}

impl MempoolHistory {
    /// Open (or create) the log at `$net_datadir/mempool_history.log`
    /// and seed the ring from its tail.
    pub fn open(net_datadir: &std::path::Path, capacity: usize) -> std::io::Result<Self> {
        let path = net_datadir.join("mempool_history.log");
        let ring = seed_ring_from_file(&path, capacity);
        let last_sig = ring.back().map(SnapshotSig::from);
        Ok(Self {
            path,
            ring: Mutex::new(ring),
            capacity,
            last_sig: Mutex::new(last_sig),
        })
    }

    /// Record a snapshot if it differs from the previous one. Returns
    /// `true` if a new record was persisted. Dedupe compares the full
    /// snapshot content (minus timestamp), so histogram-only shifts
    /// still get recorded even if size/bytes/extremes are unchanged.
    pub fn record_if_changed(&self, snapshot: MempoolSnapshot) -> bool {
        let sig = SnapshotSig::from(&snapshot);
        {
            let mut last = self.last_sig.lock().unwrap();
            if last.as_ref() == Some(&sig) {
                return false;
            }
            *last = Some(sig);
        }
        self.record(snapshot);
        true
    }

    /// Append a snapshot unconditionally. Writes JSONL to disk first,
    /// then pushes into the ring. Persistence failures are logged but
    /// do not propagate — history is best-effort.
    pub fn record(&self, snapshot: MempoolSnapshot) {
        match serde_json::to_string(&snapshot) {
            Ok(line) => {
                if let Err(e) = append_jsonl(&self.path, &line) {
                    tracing::warn!(
                        error = %e,
                        path = ?self.path,
                        "Failed to append mempool snapshot to disk"
                    );
                }
            }
            Err(e) => tracing::warn!(error = %e, "Failed to serialize mempool snapshot"),
        }

        let mut ring = self.ring.lock().unwrap();
        ring.push_back(snapshot);
        while ring.len() > self.capacity {
            ring.pop_front();
        }
    }

    /// Snapshots newer than `since_secs` seconds ago, oldest first.
    pub fn history(&self, since_secs: u64) -> Vec<MempoolSnapshot> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cutoff = now.saturating_sub(since_secs);
        let ring = self.ring.lock().unwrap();
        ring.iter()
            .filter(|s| s.ts_unix_secs >= cutoff)
            .cloned()
            .collect()
    }
}

/// Build a `MempoolSnapshot` from the current mempool state. Reuses
/// `estimate::build_histogram` for bucketing so the histogram
/// boundaries stay in sync with the live estimator.
pub fn snapshot_from_mempool(mempool: &Mempool) -> MempoolSnapshot {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let info = mempool.info();
    let entries_vec = mempool.get_all_entries();
    let (min_rate, max_rate) = extremes(&entries_vec);
    let entries_map: std::collections::HashMap<Txid, MempoolEntry> =
        entries_vec.into_iter().collect();
    let histogram = crate::mempool::estimate::build_histogram(&entries_map);
    MempoolSnapshot {
        ts_unix_secs: now,
        size: info.size,
        bytes: info.bytes,
        min_fee_rate_sat_per_kvb: min_rate,
        max_fee_rate_sat_per_kvb: max_rate,
        histogram,
    }
}

fn extremes(entries: &[(Txid, MempoolEntry)]) -> (u64, u64) {
    let mut min = u64::MAX;
    let mut max = 0u64;
    for (_, e) in entries {
        min = min.min(e.fee_rate);
        max = max.max(e.fee_rate);
    }
    if entries.is_empty() {
        (0, 0)
    } else {
        (min, max)
    }
}

fn seed_ring_from_file(path: &std::path::Path, capacity: usize) -> VecDeque<MempoolSnapshot> {
    let mut ring: VecDeque<MempoolSnapshot> = VecDeque::with_capacity(capacity);
    let Ok(file) = File::open(path) else {
        return ring;
    };
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<MempoolSnapshot>(&line) {
            ring.push_back(record);
            while ring.len() > capacity {
                ring.pop_front();
            }
        }
    }
    ring
}

fn append_jsonl(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn snap(ts: u64, size: usize) -> MempoolSnapshot {
        MempoolSnapshot {
            ts_unix_secs: ts,
            size,
            bytes: size * 100,
            min_fee_rate_sat_per_kvb: 1000,
            max_fee_rate_sat_per_kvb: 10_000,
            histogram: Vec::new(),
        }
    }

    #[test]
    fn ring_caps_at_capacity() {
        let dir = tempdir().unwrap();
        let log = MempoolHistory::open(dir.path(), 3).unwrap();
        for i in 0..5 {
            log.record(snap(1_700_000_000 + i, i as usize));
        }
        let h = log.history(u64::MAX);
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].size, 2);
        assert_eq!(h[2].size, 4);
    }

    #[test]
    fn history_respects_time_window() {
        let dir = tempdir().unwrap();
        let log = MempoolHistory::open(dir.path(), 10).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        log.record(snap(now - 3600, 1)); // 1 hour ago
        log.record(snap(now - 10, 2));
        let within_1m = log.history(60);
        assert_eq!(within_1m.len(), 1);
        assert_eq!(within_1m[0].size, 2);
    }

    #[test]
    fn record_if_changed_dedups_identical_signatures() {
        let dir = tempdir().unwrap();
        let log = MempoolHistory::open(dir.path(), 10).unwrap();
        assert!(log.record_if_changed(snap(1, 5)));
        assert!(!log.record_if_changed(snap(2, 5)), "identical sig must dedupe");
        assert!(log.record_if_changed(snap(3, 6)), "different size must record");
    }

    #[test]
    fn record_if_changed_sees_histogram_only_shifts() {
        // Regression: size/bytes/min/max can stay constant while the
        // histogram reshuffles (e.g., one 10-sat/vB tx replaced by one
        // 8-sat/vB tx — same count, same bytes, same extremes if those
        // happened to coincide). The dedupe signature must include the
        // histogram so these snapshots still record.
        let dir = tempdir().unwrap();
        let log = MempoolHistory::open(dir.path(), 10).unwrap();
        let a = MempoolSnapshot {
            ts_unix_secs: 1,
            size: 2,
            bytes: 500,
            min_fee_rate_sat_per_kvb: 5_000,
            max_fee_rate_sat_per_kvb: 10_000,
            histogram: vec![
                HistogramBucket { feerate_sat_per_kvb: 5_000, weight: 400 },
                HistogramBucket { feerate_sat_per_kvb: 10_000, weight: 400 },
            ],
        };
        let b = MempoolSnapshot {
            ts_unix_secs: 2,
            size: 2,
            bytes: 500,
            min_fee_rate_sat_per_kvb: 5_000,
            max_fee_rate_sat_per_kvb: 10_000,
            // Same size/bytes/extremes, but weight moved between buckets.
            histogram: vec![
                HistogramBucket { feerate_sat_per_kvb: 5_000, weight: 700 },
                HistogramBucket { feerate_sat_per_kvb: 10_000, weight: 100 },
            ],
        };
        assert!(log.record_if_changed(a));
        assert!(
            log.record_if_changed(b),
            "histogram-only change must be recorded, not deduped"
        );
        let h = log.history(u64::MAX);
        assert_eq!(h.len(), 2, "both snapshots must land in the ring");
    }

    #[test]
    fn seeds_from_file_on_reopen() {
        let dir = tempdir().unwrap();
        {
            let log = MempoolHistory::open(dir.path(), 10).unwrap();
            log.record(snap(1_700_000_000, 7));
        }
        let reopened = MempoolHistory::open(dir.path(), 10).unwrap();
        let h = reopened.history(u64::MAX);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].size, 7);
    }
}
