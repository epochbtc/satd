//! Durable record that a chainstate rebuild is in progress.
//!
//! `-reindex` and `-reindex-chainstate` wipe state and then rebuild it from
//! the block files. The wipe stamps the current schema version and marks
//! every index complete before the rebuild has connected a single block, so
//! a rebuild cut short (a kill, a power cut, a container stop) leaves a
//! datadir that reads as finished while its UTXO set and indexes end at
//! whatever height the last durable flush reached. Nothing else on disk
//! records the difference.
//!
//! This marker does. `satd` writes it before the wipe and removes it only
//! once the rebuild has completed, and reads it before opening the chain
//! database, so a start after an interrupted rebuild can refuse (or, with
//! `-upgradechainstate`, restart the rebuild) instead of serving the
//! truncated state. It sits in the network datadir beside the
//! clean-shutdown marker.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Filename of the marker inside the network datadir.
pub const MARKER_FILENAME: &str = ".chainstate_rebuild";

/// Which rebuild was in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RebuildKind {
    /// `-reindex-chainstate` (or an `-upgradechainstate` rebuild): the block
    /// index is intact and only the chainstate is being rebuilt.
    Chainstate,
    /// `-reindex`: the block index itself is being rebuilt from the block
    /// files, so only another `-reindex` can finish the job.
    Full,
}

/// The marker's contents. Everything but `kind` is for the operator-facing
/// message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuildMarker {
    pub kind: RebuildKind,
    /// When the rebuild started, in Unix time (seconds).
    pub started_unix: u64,
    /// The satd version that started it.
    pub satd_version: String,
    /// The chainstate schema version it was rebuilding to.
    pub schema: u32,
    /// The tip height before the wipe, when there was one.
    pub prev_tip_height: Option<u32>,
}

impl RebuildMarker {
    /// A marker for a rebuild starting now.
    pub fn now(
        kind: RebuildKind,
        satd_version: &str,
        schema: u32,
        prev_tip_height: Option<u32>,
    ) -> Self {
        Self {
            kind,
            started_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            satd_version: satd_version.to_string(),
            schema,
            prev_tip_height,
        }
    }
}

/// What [`read`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    Marker(RebuildMarker),
    /// A marker file exists but cannot be read or parsed. Still a marker:
    /// its presence alone says a rebuild did not finish, and which kind is
    /// unknown.
    Unreadable(String),
}

/// The marker path for a network-scoped datadir.
pub fn path(net_datadir: &Path) -> PathBuf {
    net_datadir.join(MARKER_FILENAME)
}

/// Read the marker, if there is one.
pub fn read(net_datadir: &Path) -> Option<Found> {
    let p = path(net_datadir);
    let bytes = match fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => return Some(Found::Unreadable(e.to_string())),
    };
    match serde_json::from_slice::<RebuildMarker>(&bytes) {
        Ok(m) => Some(Found::Marker(m)),
        Err(e) => Some(Found::Unreadable(e.to_string())),
    }
}

/// Write the marker durably: a temporary file, synced, renamed over the
/// marker, then the directory synced so the rename itself survives a power
/// cut. The caller must not start the wipe unless this returns `Ok`.
pub fn write(net_datadir: &Path, marker: &RebuildMarker) -> io::Result<()> {
    let body = serde_json::to_vec(marker).map_err(io::Error::other)?;
    let final_path = path(net_datadir);
    let tmp_path = final_path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(&body)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, &final_path)?;
    sync_dir(net_datadir)
}

/// Remove the marker durably. Absent is success.
pub fn remove(net_datadir: &Path) -> io::Result<()> {
    match fs::remove_file(path(net_datadir)) {
        Ok(()) => sync_dir(net_datadir),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// fsync a directory so a rename or unlink in it is durable. Unix only; on
/// other platforms directories cannot be opened for syncing and the rename
/// is as durable as the platform makes it.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_marker_round_trips() {
        let dir = tempdir();
        let m = RebuildMarker::now(RebuildKind::Chainstate, "0.6.0", 7, Some(967_870));
        write(dir.path(), &m).unwrap();
        assert_eq!(read(dir.path()), Some(Found::Marker(m.clone())));
        assert!(
            !path(dir.path()).with_extension("tmp").exists(),
            "the temporary file is renamed away"
        );

        let full = RebuildMarker::now(RebuildKind::Full, "0.6.0", 7, None);
        write(dir.path(), &full).unwrap();
        assert_eq!(read(dir.path()), Some(Found::Marker(full)), "a rewrite replaces it");

        remove(dir.path()).unwrap();
        assert_eq!(read(dir.path()), None);
        remove(dir.path()).expect("removing an absent marker is not an error");
    }

    #[test]
    fn a_missing_marker_reads_as_none() {
        assert_eq!(read(tempdir().path()), None);
    }

    /// A marker whose contents cannot be parsed still says a rebuild did not
    /// finish. Reading it as absent would start the node on the truncated
    /// state the marker exists to catch.
    #[test]
    fn a_corrupt_marker_still_counts_as_a_marker() {
        let dir = tempdir();
        for body in [&b"{\"kind\":\"chainst"[..], b"", b"\xff\xfe"] {
            fs::write(path(dir.path()), body).unwrap();
            assert!(
                matches!(read(dir.path()), Some(Found::Unreadable(_))),
                "{body:?} must read as an unreadable marker"
            );
        }
    }

    /// The kinds are spelled out on disk, so the file is legible to an
    /// operator and a later version can read an earlier one's marker.
    #[test]
    fn the_marker_is_plain_json_with_the_kind_spelled_out() {
        let dir = tempdir();
        write(
            dir.path(),
            &RebuildMarker {
                kind: RebuildKind::Full,
                started_unix: 1_790_000_000,
                satd_version: "0.6.0".into(),
                schema: 7,
                prev_tip_height: None,
            },
        )
        .unwrap();
        let text = fs::read_to_string(path(dir.path())).unwrap();
        assert_eq!(
            text,
            "{\"kind\":\"full\",\"started_unix\":1790000000,\"satd_version\":\"0.6.0\",\
             \"schema\":7,\"prev_tip_height\":null}\n"
        );
    }
}
