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
}
