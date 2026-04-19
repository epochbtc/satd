//! Clean-shutdown marker: a single file whose presence at startup indicates
//! the previous process exited after a successful coin-cache flush.
//!
//! The marker is a pure operator-facing signal. Even when it is absent, the
//! node recovers correctly via the existing `DataStored → Valid` replay path
//! in the IBD connect loop — so no durability logic depends on it. What the
//! marker buys us is:
//!
//! - Visibility: `getsysteminfo` and the TUI can tell the operator whether
//!   the last shutdown was clean, surfacing dirty-shutdown cases that might
//!   otherwise go unnoticed on slow hardware (Umbrel, Pi).
//! - A foothold for future optimizations (e.g. skipping scans that only
//!   matter after a dirty exit).
//!
//! The marker contains a small JSON payload with the observed tip hash,
//! tip height, and shutdown timestamp. The contents are advisory — if the
//! file is malformed we treat it as "not present" and log a warning.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::storage::StoreError;

/// Outcome of awaiting a bounded shutdown flush. The main binary uses this
/// to decide whether to write the clean-shutdown marker, log an error, or
/// force-exit with `std::process::exit(1)` — the only way to actually
/// honor `--max-shutdown-secs` when the flush is stuck inside a blocking
/// FFI call that tokio cannot abort.
#[derive(Debug, PartialEq, Eq)]
pub enum BoundedFlushOutcome {
    /// Flush completed successfully within the deadline; marker may be written.
    Clean,
    /// Flush ran to completion but returned an error; no marker.
    FlushError(String),
    /// The oneshot sender was dropped before signalling (thread panic?).
    ChannelDropped,
    /// Flush exceeded the deadline. Caller MUST force the process to exit —
    /// the underlying `spawn_blocking` or `std::thread` task cannot be
    /// aborted, so any normal return would let the runtime wait for it.
    TimedOut,
}

/// Await a flush completion signal with a hard deadline.
///
/// Extracted so unit tests can exercise the timeout arbitration logic
/// without needing a running satd. The main binary wires the sender side
/// to a dedicated `std::thread` that calls `flush_coin_cache`.
pub async fn await_bounded_flush(
    flush_rx: tokio::sync::oneshot::Receiver<Result<(), StoreError>>,
    deadline: Duration,
) -> BoundedFlushOutcome {
    match tokio::time::timeout(deadline, flush_rx).await {
        Ok(Ok(Ok(()))) => BoundedFlushOutcome::Clean,
        Ok(Ok(Err(e))) => BoundedFlushOutcome::FlushError(e.to_string()),
        Ok(Err(_)) => BoundedFlushOutcome::ChannelDropped,
        Err(_) => BoundedFlushOutcome::TimedOut,
    }
}

/// Filename of the marker inside the network datadir.
pub const MARKER_FILENAME: &str = ".clean_shutdown";

/// Payload written into the marker. All fields are advisory. Missing or
/// malformed fields are tolerated — the marker's *presence* is the signal.
#[derive(Debug, Clone)]
pub struct CleanShutdownRecord {
    pub tip_hash: String,
    pub tip_height: u32,
    pub shutdown_unix_secs: u64,
}

/// Return the marker path for a given network-scoped datadir.
pub fn marker_path(net_datadir: &Path) -> PathBuf {
    net_datadir.join(MARKER_FILENAME)
}

/// Called once at startup, before opening the chain database.
///
/// If a marker exists we unlink it and return its parsed contents. The
/// unlink happens *before* any mutable work, so a crash during startup
/// leaves us correctly detecting "dirty" on the next run.
pub fn consume_marker(net_datadir: &Path) -> Option<CleanShutdownRecord> {
    let path = marker_path(net_datadir);
    let contents = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(?path, error = %e, "Could not read clean-shutdown marker; treating as dirty");
            let _ = fs::remove_file(&path);
            return None;
        }
    };

    // Best-effort unlink. We proceed with whatever we read even if unlink
    // fails — worst case we'll re-read the same contents next run.
    if let Err(e) = fs::remove_file(&path) {
        tracing::warn!(?path, error = %e, "Could not unlink clean-shutdown marker");
    }

    match parse_record(&contents) {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Clean-shutdown marker malformed; treating as dirty (marker unlinked)"
            );
            None
        }
    }
}

/// Called at the end of graceful shutdown, *after* `flush_coin_cache` +
/// `flush_durable` have succeeded within the configured timeout. Writes a
/// small JSON record atomically (write-tmp + rename).
pub fn write_marker(net_datadir: &Path, tip_hash: &str, tip_height: u32) -> io::Result<()> {
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = format!(
        "{{\"tip_hash\":\"{}\",\"tip_height\":{},\"shutdown_unix_secs\":{}}}\n",
        tip_hash, tip_height, unix_secs
    );
    let final_path = marker_path(net_datadir);
    let tmp_path = final_path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

fn parse_record(s: &str) -> Result<CleanShutdownRecord, String> {
    // Deliberately no serde dependency — the fields are simple and the
    // forward-compat story is "ignore unknown, fall back to defaults".
    let trimmed = s.trim();
    let inner = trimmed
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| "not a JSON object".to_string())?;
    let mut tip_hash: Option<String> = None;
    let mut tip_height: Option<u32> = None;
    let mut shutdown_unix_secs: Option<u64> = None;
    for field in inner.split(',') {
        let (k, v) = field
            .split_once(':')
            .ok_or_else(|| format!("malformed field: {field}"))?;
        let k = k.trim().trim_matches('"');
        let v = v.trim();
        match k {
            "tip_hash" => tip_hash = Some(v.trim_matches('"').to_string()),
            "tip_height" => tip_height = v.parse().ok(),
            "shutdown_unix_secs" => shutdown_unix_secs = v.parse().ok(),
            _ => {}
        }
    }
    Ok(CleanShutdownRecord {
        tip_hash: tip_hash.unwrap_or_default(),
        tip_height: tip_height.unwrap_or(0),
        shutdown_unix_secs: shutdown_unix_secs.unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "satd-shutdown-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn consume_returns_none_when_missing() {
        let dir = tempdir();
        assert!(consume_marker(&dir).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_then_consume_roundtrips_fields() {
        let dir = tempdir();
        write_marker(&dir, "abc123", 1234).unwrap();
        assert!(marker_path(&dir).exists());
        let rec = consume_marker(&dir).unwrap();
        assert_eq!(rec.tip_hash, "abc123");
        assert_eq!(rec.tip_height, 1234);
        // Marker should be unlinked after consumption.
        assert!(!marker_path(&dir).exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn consume_unlinks_even_when_malformed() {
        let dir = tempdir();
        fs::write(marker_path(&dir), b"this is not json").unwrap();
        assert!(consume_marker(&dir).is_none());
        assert!(
            !marker_path(&dir).exists(),
            "malformed marker must be unlinked"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_overwrites_existing_marker_atomically() {
        let dir = tempdir();
        write_marker(&dir, "first", 1).unwrap();
        write_marker(&dir, "second", 2).unwrap();
        // No stale .tmp file left behind.
        assert!(!marker_path(&dir).with_extension("tmp").exists());
        let rec = consume_marker(&dir).unwrap();
        assert_eq!(rec.tip_hash, "second");
        assert_eq!(rec.tip_height, 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_record_tolerates_unknown_fields() {
        let rec = parse_record(
            r#"{"tip_hash":"x","tip_height":42,"shutdown_unix_secs":99,"future_field":123}"#,
        )
        .unwrap();
        assert_eq!(rec.tip_hash, "x");
        assert_eq!(rec.tip_height, 42);
        assert_eq!(rec.shutdown_unix_secs, 99);
    }

    // ----------------------------------------------------------------
    // await_bounded_flush — exercises the timeout arbitration logic so
    // we can prove the TimedOut branch fires when a flush doesn't
    // complete in time. The main binary translates TimedOut into
    // std::process::exit(1), which is what actually bounds shutdown.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn bounded_flush_clean_on_immediate_ok() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tx.send(Ok(())).unwrap();
        let outcome = await_bounded_flush(rx, Duration::from_secs(5)).await;
        assert_eq!(outcome, BoundedFlushOutcome::Clean);
    }

    #[tokio::test]
    async fn bounded_flush_surfaces_flush_error() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tx.send(Err(crate::storage::StoreError::Database("boom".into())))
            .unwrap();
        let outcome = await_bounded_flush(rx, Duration::from_secs(5)).await;
        match outcome {
            BoundedFlushOutcome::FlushError(msg) => assert!(msg.contains("boom")),
            other => panic!("expected FlushError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn bounded_flush_channel_dropped_when_sender_gone() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), StoreError>>();
        drop(tx);
        let outcome = await_bounded_flush(rx, Duration::from_secs(5)).await;
        assert_eq!(outcome, BoundedFlushOutcome::ChannelDropped);
    }

    #[tokio::test]
    async fn bounded_flush_times_out_when_sender_is_slow() {
        // Keep the sender alive but never signal. The deadline should fire
        // and the outcome must be TimedOut — which the main binary reacts
        // to by calling std::process::exit(1), the actual enforcement of
        // --max-shutdown-secs.
        let (_tx_kept_alive, rx) = tokio::sync::oneshot::channel::<Result<(), StoreError>>();
        let t0 = std::time::Instant::now();
        let outcome = await_bounded_flush(rx, Duration::from_millis(50)).await;
        let elapsed = t0.elapsed();
        assert_eq!(outcome, BoundedFlushOutcome::TimedOut);
        // Deadline must have been honored (within a generous slack for CI
        // scheduling jitter).
        assert!(
            elapsed < Duration::from_millis(500),
            "timeout should fire quickly; elapsed={:?}",
            elapsed
        );
    }
}
