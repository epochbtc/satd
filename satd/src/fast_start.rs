//! AssumeUTXO `--fast-start`: download a UTXO snapshot from an operator-
//! supplied source (an `https://` URL or a local file) and load it at
//! startup, automating the otherwise-manual `loadtxoutset` step.
//!
//! Trust model: the snapshot's integrity is gated by satd's hardcoded
//! AssumeUTXO anchor hash, re-checked by `load_txout_set` at load time — a
//! tampered or wrong file is rejected and rolled back regardless of where it
//! came from. This module adds two things on top: HTTPS transport security
//! (plain `http://` is refused at config time; certificates are validated)
//! and startup orchestration. There is deliberately **no** P2P snapshot
//! distribution — the operator names the source.
//!
//! Surfaces split across satd's two startup phases so progress is visible
//! the same way a reindex is:
//!   * [`download_phase`] runs **before** the RPC server binds, reporting
//!     bytes through [`StartupProgress`] so the pre-RPC TUI panel renders a
//!     gauge (phase `fast_start_download`). A failure here exits the process
//!     before the node ever advertises readiness.
//!   * [`load_when_ready`] runs **after** the node is up: it waits for P2P
//!     header sync to reach the anchor height (visible as normal IBD), then
//!     loads the snapshot. The genesis→snapshot background re-validation is
//!     then visible through `getchainstates`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use node::chain::assumeutxo;
use node::chain::state::ChainState;
use node::startup_progress::StartupProgress;
use node::storage::compressed_coin::SnapshotMetadata;

/// File name the downloaded snapshot is written to inside the network
/// datadir. Removed after a successful load.
const SNAPSHOT_FILENAME: &str = "fast-start-snapshot.dat";

/// How many times to (re)attempt the download before giving up. Each
/// attempt resumes from the bytes already on disk via an HTTP Range
/// request, so a transient drop costs only the un-fetched tail.
const MAX_DOWNLOAD_ATTEMPTS: u32 = 5;

/// Read buffer for the streaming copy. 1 MiB keeps syscall overhead low
/// without holding much memory.
const COPY_BUF_BYTES: usize = 1 << 20;

/// Where a fast-start snapshot comes from.
#[derive(Debug)]
pub enum Source {
    /// Remote `https://` URL — downloaded (resumably) into the datadir.
    Https(String),
    /// A local file already on disk (bare path or `file://`). Used in place.
    Local(PathBuf),
}

impl Source {
    /// Classify a raw `--fast-start` value. Mirrors the config-time
    /// validation: remote sources must be `https://`; a bare path or
    /// `file://` is the operator's own disk.
    pub fn parse(raw: &str) -> Result<Source, String> {
        if let Some(rest) = raw.strip_prefix("file://") {
            return Ok(Source::Local(PathBuf::from(rest)));
        }
        if let Some((scheme, _)) = raw.split_once("://") {
            if scheme.eq_ignore_ascii_case("https") {
                return Ok(Source::Https(raw.to_string()));
            }
            if scheme.eq_ignore_ascii_case("http") {
                return Err(
                    "--fast-start requires https:// (plain http:// is refused)".to_string(),
                );
            }
            return Err(format!("--fast-start scheme '{scheme}://' is unsupported"));
        }
        Ok(Source::Local(PathBuf::from(raw)))
    }
}

/// True when the datadir has no chainstate to bootstrap onto — i.e. a fresh
/// node with the tip still at genesis and no in-flight AssumeUTXO snapshot.
/// `--fast-start` is a no-op on an already-initialized node.
pub fn node_is_fresh(chain_state: &ChainState, net_datadir: &Path) -> bool {
    chain_state.tip_height() == 0 && !net_datadir.join("chainstate_background").exists()
}

/// Pre-RPC startup phase: materialize the snapshot file locally, reporting
/// progress through `progress`. Returns the local path of the snapshot
/// (whether downloaded or operator-supplied) for [`load_when_ready`].
///
/// Interruptible: a Ctrl+C / SIGTERM during the download aborts and returns
/// an error so the caller can exit cleanly.
pub async fn download_phase(
    raw_source: &str,
    net_datadir: &Path,
    progress: Arc<StartupProgress>,
) -> Result<PathBuf, String> {
    let source = Source::parse(raw_source)?;

    match source {
        Source::Local(path) => {
            if !path.exists() {
                return Err(format!("snapshot file not found: {}", path.display()));
            }
            tracing::info!(path = %path.display(), "fast-start: using local snapshot file");
            Ok(path)
        }
        Source::Https(url) => {
            let dest = net_datadir.join(SNAPSHOT_FILENAME);
            progress.set_phase("fast_start_download", "Downloading AssumeUTXO snapshot");

            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(|e| format!("registering SIGTERM handler: {e}"))?;

            let mut last_err = String::new();
            for attempt in 1..=MAX_DOWNLOAD_ATTEMPTS {
                tracing::info!(
                    attempt,
                    max = MAX_DOWNLOAD_ATTEMPTS,
                    url = %url,
                    "fast-start: downloading snapshot (resumable)"
                );
                let url_c = url.clone();
                let dest_c = dest.clone();
                let progress_c = progress.clone();
                let download =
                    tokio::task::spawn_blocking(move || download_blocking(&url_c, &dest_c, &progress_c));

                tokio::select! {
                    joined = download => {
                        match joined.map_err(|e| format!("download task panicked: {e}"))? {
                            Ok(()) => return Ok(dest),
                            Err(e) => {
                                last_err = e;
                                tracing::warn!(attempt, error = %last_err, "fast-start: download attempt failed");
                            }
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        return Err("interrupted by Ctrl+C during snapshot download".to_string());
                    }
                    _ = sigterm.recv() => {
                        return Err("interrupted by SIGTERM during snapshot download".to_string());
                    }
                }

                // Linear backoff before the next resume attempt, interruptible.
                let backoff = Duration::from_secs(5 * attempt as u64);
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = tokio::signal::ctrl_c() => {
                        return Err("interrupted by Ctrl+C during snapshot download".to_string());
                    }
                    _ = sigterm.recv() => {
                        return Err("interrupted by SIGTERM during snapshot download".to_string());
                    }
                }
            }
            Err(format!(
                "snapshot download failed after {MAX_DOWNLOAD_ATTEMPTS} attempts: {last_err}"
            ))
        }
    }
}

/// How to continue a download given what's already on disk and how the
/// server answered the resume request.
#[derive(Debug, PartialEq, Eq)]
struct ResumePlan {
    /// Append to the existing file (server honored the Range) vs. rewrite
    /// it from scratch (fresh download, or server ignored the Range).
    append: bool,
    /// Expected size of the finished file, if the server told us.
    total: Option<u64>,
    /// Byte offset the body we're about to receive starts at.
    start: u64,
}

/// Decide how to resume. `partial_content` is whether the response was
/// `206 Partial Content`; `body_len` is its `Content-Length` (the tail
/// length for a 206, the whole-file length for a 200).
fn resume_plan(existing: u64, partial_content: bool, body_len: Option<u64>) -> ResumePlan {
    let resuming = existing > 0 && partial_content;
    ResumePlan {
        append: resuming,
        total: body_len.map(|l| if resuming { existing + l } else { l }),
        start: if resuming { existing } else { 0 },
    }
}

/// Blocking, resumable HTTPS download. Runs inside `spawn_blocking`.
///
/// Resume: if `dest` already holds bytes, request `Range: bytes=<len>-`. A
/// `206 Partial Content` response is appended; a `200 OK` (server ignored
/// the range) restarts the file from scratch. Certificates are validated by
/// reqwest's default rustls verifier — never disabled.
fn download_blocking(url: &str, dest: &Path, progress: &StartupProgress) -> Result<(), String> {
    use reqwest::header::{CONTENT_LENGTH, RANGE};

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("building HTTPS client: {e}"))?;

    let existing = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    let mut req = client.get(url);
    if existing > 0 {
        req = req.header(RANGE, format!("bytes={existing}-"));
    }
    let mut resp = req.send().map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("server returned HTTP {status}"));
    }

    // Did the server honor our resume request?
    let partial = status == reqwest::StatusCode::PARTIAL_CONTENT;
    let body_len = resp
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let plan = resume_plan(existing, partial, body_len);
    if let Some(t) = plan.total {
        progress.set_total(t);
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(plan.append)
        .truncate(!plan.append)
        .open(dest)
        .map_err(|e| format!("opening {}: {e}", dest.display()))?;

    let mut written: u64 = plan.start;
    progress.set_current(written);
    let mut buf = vec![0u8; COPY_BUF_BYTES];
    loop {
        let n = resp
            .read(&mut buf)
            .map_err(|e| format!("read from server failed: {e}"))?;
        if n == 0 {
            break;
        }
        use std::io::Write;
        file.write_all(&buf[..n])
            .map_err(|e| format!("write to {} failed: {e}", dest.display()))?;
        written += n as u64;
        progress.set_current(written);
    }
    file.sync_all()
        .map_err(|e| format!("fsync {} failed: {e}", dest.display()))?;
    Ok(())
}

/// Post-ready task: wait for P2P header sync to reach the snapshot's anchor
/// height, then load it. The load itself (`load_txout_set`) re-verifies the
/// snapshot against the hardcoded anchor hash and rolls back on mismatch —
/// the authoritative integrity gate. On success the downloaded file is
/// removed (operator-supplied local files are left untouched).
pub async fn load_when_ready(
    chain_state: Arc<ChainState>,
    net_datadir: PathBuf,
    local_path: PathBuf,
    prune_target: u64,
    dbcache_mb: u64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    // Peek the header to discover which anchor the snapshot claims, so we
    // know the header height we must sync to before loading.
    let anchor = {
        let mut f = std::fs::File::open(&local_path)
            .map_err(|e| format!("opening snapshot {}: {e}", local_path.display()))?;
        let meta = SnapshotMetadata::deserialize(&mut f)
            .map_err(|e| format!("invalid snapshot header: {e}"))?;
        assumeutxo::lookup_by_blockhash(chain_state.network, &meta.base_blockhash).ok_or_else(
            || {
                format!(
                    "snapshot base block {} is not a recognized AssumeUTXO anchor for this network",
                    meta.base_blockhash
                )
            },
        )?
    };
    tracing::info!(
        height = anchor.height,
        hash = %anchor.blockhash,
        "fast-start: snapshot anchor recognized; waiting for header sync to reach it"
    );

    // Wait for headers. They are tiny, so this is normally quick and shows
    // up as ordinary IBD header progress in the full TUI.
    loop {
        if *shutdown_rx.borrow() {
            return Err("shutdown while waiting for header sync".to_string());
        }
        if chain_state.headers_tip_height() >= anchor.height {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
            _ = shutdown_rx.changed() => {}
        }
    }

    tracing::info!("fast-start: headers synced past anchor; loading snapshot UTXO set");
    let path_str = local_path.to_string_lossy().to_string();
    let cs = chain_state.clone();
    let dd = net_datadir.clone();
    let load_res = tokio::task::spawn_blocking(move || {
        node::rpc::blockchain::load_txout_set(cs.as_ref(), &dd, prune_target, dbcache_mb, &path_str)
    })
    .await
    .map_err(|e| format!("load task panicked: {e}"))?;

    match load_res {
        Ok(v) => {
            tracing::info!(
                result = %v,
                "fast-start: snapshot loaded; serving the snapshot tip while the background \
                 validator catches up from genesis (see getchainstates)"
            );
            // Reclaim the ~GB download once it has been consumed.
            remove_downloaded(&local_path, &net_datadir);
            Ok(())
        }
        Err((code, msg)) => {
            // Drop a rejected download so the next start re-fetches a fresh
            // copy rather than re-loading the same bad bytes in a restart
            // loop. (A wrong-anchor file will keep failing — that's an
            // operator error to fix — but a corrupt transfer self-heals.)
            remove_downloaded(&local_path, &net_datadir);
            Err(format!(
                "loadtxoutset rejected the snapshot (code {code}): {msg}"
            ))
        }
    }
}

/// Remove the snapshot file iff it's the one we downloaded into the datadir.
/// A user-supplied local path (anything else) is left untouched.
fn remove_downloaded(local_path: &Path, net_datadir: &Path) {
    if local_path == net_datadir.join(SNAPSHOT_FILENAME)
        && let Err(e) = std::fs::remove_file(local_path)
    {
        tracing::warn!(error = %e, path = %local_path.display(), "fast-start: could not remove snapshot file");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_plain_http() {
        let err = Source::parse("http://example.com/utxo.dat").unwrap_err();
        assert!(err.contains("https://"), "got: {err}");
    }

    #[test]
    fn parse_accepts_https() {
        match Source::parse("https://example.com/utxo.dat").unwrap() {
            Source::Https(u) => assert_eq!(u, "https://example.com/utxo.dat"),
            Source::Local(_) => panic!("expected Https"),
        }
    }

    #[test]
    fn parse_file_url_is_local() {
        match Source::parse("file:///srv/snapshots/utxo.dat").unwrap() {
            Source::Local(p) => assert_eq!(p, PathBuf::from("/srv/snapshots/utxo.dat")),
            Source::Https(_) => panic!("expected Local"),
        }
    }

    #[test]
    fn parse_bare_path_is_local() {
        match Source::parse("/opt/utxo-840000.dat").unwrap() {
            Source::Local(p) => assert_eq!(p, PathBuf::from("/opt/utxo-840000.dat")),
            Source::Https(_) => panic!("expected Local"),
        }
    }

    #[test]
    fn parse_rejects_unknown_scheme() {
        assert!(Source::parse("ftp://host/utxo.dat").is_err());
    }

    #[test]
    fn resume_plan_fresh_download() {
        // Nothing on disk, normal 200 with a known length.
        let p = resume_plan(0, false, Some(100));
        assert_eq!(
            p,
            ResumePlan { append: false, total: Some(100), start: 0 }
        );
    }

    #[test]
    fn resume_plan_server_honors_range() {
        // 40 bytes on disk, 206 with a 60-byte tail → append, total 100.
        let p = resume_plan(40, true, Some(60));
        assert_eq!(
            p,
            ResumePlan { append: true, total: Some(100), start: 40 }
        );
    }

    #[test]
    fn resume_plan_server_ignores_range() {
        // 40 bytes on disk but the server sent a full 200 → restart from 0.
        let p = resume_plan(40, false, Some(100));
        assert_eq!(
            p,
            ResumePlan { append: false, total: Some(100), start: 0 }
        );
    }

    #[test]
    fn resume_plan_without_content_length() {
        // No Content-Length: total is unknown, but we still download.
        let p = resume_plan(0, false, None);
        assert_eq!(p, ResumePlan { append: false, total: None, start: 0 });
    }
}
