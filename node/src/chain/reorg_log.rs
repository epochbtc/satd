//! Persistent reorg history + optional webhook dispatch.
//!
//! Every time `perform_reorg` completes we record a small JSON record
//! with the fork point, old/new tips, and the disconnected/reconnected
//! block hashes. Records go to two places:
//!
//! - An in-memory ring buffer (default: last 256) — cheap O(1) reads
//!   for `getreorghistory`, the TUI, and health checks.
//! - An append-only JSONL file at `$net_datadir/reorg.log` — fsynced
//!   per write (reorgs are rare; correctness beats throughput). The
//!   ring is seeded from this file on startup so history survives
//!   restarts.
//!
//! If a webhook sender is wired in, each record is best-effort forwarded
//! through an `mpsc::Sender`. A full queue *drops and counts* rather
//! than blocking consensus — the chain processing path must never wait
//! on external HTTP.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::BlockHash;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Default cap for the in-memory ring. 256 is small enough to ignore
/// (~50 KiB) and more than enough operator surface.
pub const DEFAULT_RING_CAPACITY: usize = 256;

/// One persisted reorg event. Intentionally flat: we want the JSONL
/// log to stay human-readable under `jq` or a one-line grep.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReorgRecord {
    pub ts_unix_secs: u64,
    /// Depth measured as `old_height - fork_height` (blocks rolled back).
    pub depth: u32,
    pub fork_height: u32,
    pub old_tip: String,
    pub new_tip: String,
    /// Hashes of blocks disconnected during this reorg, in the order
    /// we rolled them back (old-tip-first, fork-parent-last).
    pub disconnected: Vec<String>,
    /// Hashes of blocks reconnected into the new chain (fork-parent-
    /// first, new-tip-last). May be empty if the active tip was the
    /// fork parent before the reorg finished.
    pub reconnected: Vec<String>,
}

impl ReorgRecord {
    /// Build a record from the key data available at `perform_reorg`.
    pub fn new(
        fork_height: u32,
        old_tip: BlockHash,
        new_tip: BlockHash,
        old_height: u32,
        disconnected: Vec<BlockHash>,
        reconnected: Vec<BlockHash>,
    ) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let depth = old_height.saturating_sub(fork_height);
        Self {
            ts_unix_secs: ts,
            depth,
            fork_height,
            old_tip: old_tip.to_string(),
            new_tip: new_tip.to_string(),
            disconnected: disconnected.iter().map(|h| h.to_string()).collect(),
            reconnected: reconnected.iter().map(|h| h.to_string()).collect(),
        }
    }
}

/// In-process reorg log + optional webhook sender.
pub struct ReorgLog {
    path: PathBuf,
    ring: Mutex<VecDeque<ReorgRecord>>,
    capacity: usize,
    webhook_tx: Mutex<Option<mpsc::Sender<ReorgRecord>>>,
    /// Number of records the webhook channel dropped because the queue
    /// was full. Exposed for observability, never read to gate consensus.
    webhook_drops: AtomicU64,
}

impl ReorgLog {
    /// Open (or create) the log file at `$net_datadir/reorg.log` and
    /// seed the ring from its last `capacity` records.
    pub fn open(net_datadir: &std::path::Path, capacity: usize) -> std::io::Result<Self> {
        let path = net_datadir.join("reorg.log");
        let ring = seed_ring_from_file(&path, capacity);
        Ok(Self {
            path,
            ring: Mutex::new(ring),
            capacity,
            webhook_tx: Mutex::new(None),
            webhook_drops: AtomicU64::new(0),
        })
    }

    /// Wire a webhook sender. Subsequent `record()` calls will try to
    /// push events into it. Overwrites any previous sender.
    pub fn set_webhook_sender(&self, tx: mpsc::Sender<ReorgRecord>) {
        *self.webhook_tx.lock() = Some(tx);
    }

    /// Persist a record: append JSONL to disk, push into the ring,
    /// best-effort forward to the webhook channel if set.
    pub fn record(&self, record: ReorgRecord) {
        // Append to disk first so a crash between disk-write and ring
        // update still retains the history. Serialization failures are
        // logged and skipped — we never let a reorg log failure block
        // the connect path.
        match serde_json::to_string(&record) {
            Ok(line) => {
                if let Err(e) = append_jsonl(&self.path, &line) {
                    tracing::warn!(error = %e, path = ?self.path, "Failed to append reorg record to disk");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to serialize reorg record");
            }
        }

        {
            let mut ring = self.ring.lock();
            ring.push_back(record.clone());
            while ring.len() > self.capacity {
                ring.pop_front();
            }
        }

        // Best-effort webhook dispatch. `try_send` never blocks; a full
        // queue means the dispatcher is lagging on slow webhooks, in
        // which case dropping is correct (we still have the ring + disk).
        if let Some(tx) = self.webhook_tx.lock().as_ref()
            && tx.try_send(record).is_err()
        {
            self.webhook_drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Return records that happened within the last `since_secs`
    /// seconds, newest last.
    pub fn history(&self, since_secs: u64) -> Vec<ReorgRecord> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cutoff = now.saturating_sub(since_secs);
        let ring = self.ring.lock();
        ring.iter()
            .filter(|r| r.ts_unix_secs >= cutoff)
            .cloned()
            .collect()
    }

    /// Total records dropped from the webhook queue since startup.
    pub fn webhook_drops(&self) -> u64 {
        self.webhook_drops.load(Ordering::Relaxed)
    }
}

fn seed_ring_from_file(path: &std::path::Path, capacity: usize) -> VecDeque<ReorgRecord> {
    let mut ring = VecDeque::with_capacity(capacity);
    let Ok(file) = File::open(path) else {
        return ring;
    };
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<ReorgRecord>(line) {
            ring.push_back(rec);
            while ring.len() > capacity {
                ring.pop_front();
            }
        }
        // Bad lines are skipped silently — tolerate forward-incompatible
        // fields and corrupt tails from prior crashes.
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

    fn dummy_hash(byte: u8) -> BlockHash {
        use bitcoin::hashes::Hash;
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes))
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "satd-reorglog-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn record_roundtrips_through_ring_and_history() {
        let dir = tempdir();
        let log = ReorgLog::open(&dir, 8).unwrap();

        let rec = ReorgRecord::new(
            100,
            dummy_hash(1),
            dummy_hash(2),
            103,
            vec![dummy_hash(11), dummy_hash(12), dummy_hash(13)],
            vec![dummy_hash(21), dummy_hash(22), dummy_hash(23)],
        );
        log.record(rec.clone());

        let hist = log.history(3600);
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].depth, 3);
        assert_eq!(hist[0].disconnected.len(), 3);
        assert_eq!(hist[0].reconnected.len(), 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ring_bounds_at_capacity() {
        let dir = tempdir();
        let log = ReorgLog::open(&dir, 3).unwrap();
        for i in 0..10u8 {
            log.record(ReorgRecord::new(
                i as u32,
                dummy_hash(i),
                dummy_hash(i + 100),
                i as u32 + 1,
                vec![],
                vec![],
            ));
        }
        let hist = log.history(3600);
        assert_eq!(hist.len(), 3, "ring should cap at capacity");
        // Most recent records retained.
        assert_eq!(hist[2].fork_height, 9);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reopen_seeds_ring_from_disk() {
        let dir = tempdir();
        {
            let log = ReorgLog::open(&dir, 8).unwrap();
            log.record(ReorgRecord::new(
                5,
                dummy_hash(1),
                dummy_hash(2),
                7,
                vec![dummy_hash(10)],
                vec![dummy_hash(20)],
            ));
        }
        let log2 = ReorgLog::open(&dir, 8).unwrap();
        let hist = log2.history(3600);
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].fork_height, 5);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn history_filters_by_since_secs() {
        let dir = tempdir();
        let log = ReorgLog::open(&dir, 8).unwrap();
        // Manually push a stale record bypassing `record()` to simulate
        // a very old event.
        {
            let mut ring = log.ring.lock();
            ring.push_back(ReorgRecord {
                ts_unix_secs: 100, // ancient
                depth: 1,
                fork_height: 0,
                old_tip: "aa".into(),
                new_tip: "bb".into(),
                disconnected: vec![],
                reconnected: vec![],
            });
        }
        log.record(ReorgRecord::new(
            10,
            dummy_hash(1),
            dummy_hash(2),
            11,
            vec![],
            vec![],
        ));
        let fresh = log.history(3600);
        assert_eq!(fresh.len(), 1, "stale record filtered out");
        let all = log.history(u64::MAX);
        assert_eq!(all.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn webhook_drops_when_channel_full() {
        let dir = tempdir();
        let log = ReorgLog::open(&dir, 8).unwrap();
        let (tx, _rx) = mpsc::channel::<ReorgRecord>(1);
        log.set_webhook_sender(tx);
        for i in 0..5u8 {
            log.record(ReorgRecord::new(
                i as u32,
                dummy_hash(i),
                dummy_hash(i + 10),
                i as u32 + 1,
                vec![],
                vec![],
            ));
        }
        // Channel capacity 1, rx never drained → at least some drops.
        assert!(log.webhook_drops() > 0, "expected at least one drop");
        std::fs::remove_dir_all(&dir).ok();
    }
}
