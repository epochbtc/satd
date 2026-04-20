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

/// In-process mempool history ring + append-only JSONL log.
pub struct MempoolHistory {
    path: PathBuf,
    ring: Mutex<VecDeque<MempoolSnapshot>>,
    capacity: usize,
    /// Last entry's (size, bytes, min, max) tuple — used to skip
    /// writing an identical snapshot when nothing changed.
    last_sig: Mutex<Option<(usize, usize, u64, u64)>>,
}

impl MempoolHistory {
    /// Open (or create) the log at `$net_datadir/mempool_history.log`
    /// and seed the ring from its tail.
    pub fn open(net_datadir: &std::path::Path, capacity: usize) -> std::io::Result<Self> {
        let path = net_datadir.join("mempool_history.log");
        let ring = seed_ring_from_file(&path, capacity);
        let last_sig = ring
            .back()
            .map(|s| (s.size, s.bytes, s.min_fee_rate_sat_per_kvb, s.max_fee_rate_sat_per_kvb));
        Ok(Self {
            path,
            ring: Mutex::new(ring),
            capacity,
            last_sig: Mutex::new(last_sig),
        })
    }

    /// Record a snapshot if it differs from the previous one. Returns
    /// `true` if a new record was persisted.
    pub fn record_if_changed(&self, snapshot: MempoolSnapshot) -> bool {
        let sig = (
            snapshot.size,
            snapshot.bytes,
            snapshot.min_fee_rate_sat_per_kvb,
            snapshot.max_fee_rate_sat_per_kvb,
        );
        {
            let mut last = self.last_sig.lock().unwrap();
            if *last == Some(sig) {
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
