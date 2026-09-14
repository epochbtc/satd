//! One label per index, for the status page.
//!
//! sat-tui classified index state itself, from `getserverstatus` and
//! `getsatdindexinfo`, in its services row. The page needs the same answer,
//! and two copies of that decision would drift, so it is made here, from the
//! same `render_status` reports those RPCs are built from.

use serde::Serialize;

/// What one index is doing, as a wallet user needs to know it: is it serving
/// complete answers, and if not, how long until it is.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum IndexState {
    /// Switched off in the configuration.
    Off,
    /// Enabled and complete. Queries through it are answered in full.
    Synced,
    /// Enabled, not yet complete, and no backfill is running: the index is
    /// being written as the chain syncs.
    Syncing,
    /// A backfill is building the index over blocks the node already has.
    Backfill {
        /// 1 or 2 for the two-pass address index, absent otherwise.
        #[serde(skip_serializing_if = "Option::is_none")]
        pass: Option<u8>,
        /// 0.0..=1.0, from the backfill's own progress measure.
        progress: f64,
        cursor_height: u32,
        snapshot_height: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        eta_secs: Option<u64>,
    },
    /// A backfill was paused and resumes on `resumeindex`.
    Paused {
        #[serde(skip_serializing_if = "Option::is_none")]
        pass: Option<u8>,
        progress: f64,
    },
    /// A backfill stopped on an error. The error text is not carried: it
    /// can name paths on the host, and the page may be served with nothing
    /// in front of it. `getsatdindexinfo` reports it.
    Failed,
}

impl IndexState {
    /// Complete and serving. Anything else means answers that read through
    /// this index are partial.
    pub fn is_synced(&self) -> bool {
        matches!(self, IndexState::Synced)
    }
}

/// The classification inputs common to every index. Each index's
/// `render_status` report carries the same fields under the same names.
#[derive(Debug, Clone)]
pub struct IndexReport {
    pub enabled: bool,
    /// The index's own "complete" decision: for the address index the
    /// on-disk completeness marker, for the others `render_status`'s
    /// `synced`, which already folds in the marker and backfill quiescence.
    pub complete: bool,
    /// The backfill cursor state label: `running`, `paused`, `failed`,
    /// `completed`, `cancelled`, `rejected` or `idle`.
    pub backfill_state: String,
    pub pass: Option<u8>,
    pub progress: f64,
    pub cursor_height: u32,
    pub snapshot_height: u32,
    pub eta_secs: u64,
}

/// sat-tui's rule, unchanged: a running, paused or failed backfill is what
/// the user needs to see and takes precedence; otherwise off, synced or
/// syncing.
pub fn classify(r: &IndexReport) -> IndexState {
    let progress = r.progress.clamp(0.0, 1.0);
    match r.backfill_state.as_str() {
        "running" => {
            return IndexState::Backfill {
                pass: r.pass,
                progress,
                cursor_height: r.cursor_height,
                snapshot_height: r.snapshot_height,
                eta_secs: (r.eta_secs > 0).then_some(r.eta_secs),
            };
        }
        "paused" => return IndexState::Paused { pass: r.pass, progress },
        "failed" => return IndexState::Failed,
        _ => {}
    }
    if !r.enabled {
        IndexState::Off
    } else if r.complete {
        IndexState::Synced
    } else {
        IndexState::Syncing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(state: &str) -> IndexReport {
        IndexReport {
            enabled: true,
            complete: true,
            backfill_state: state.to_string(),
            pass: Some(2),
            progress: 0.4,
            cursor_height: 100,
            snapshot_height: 500,
            eta_secs: 60,
        }
    }

    #[test]
    fn a_visible_backfill_wins_over_the_steady_label() {
        assert!(matches!(classify(&report("running")), IndexState::Backfill { pass: Some(2), .. }));
        assert_eq!(classify(&report("paused")), IndexState::Paused { pass: Some(2), progress: 0.4 });
        assert_eq!(classify(&report("failed")), IndexState::Failed);
    }

    #[test]
    fn steady_states() {
        for idle in ["idle", "completed", "cancelled", "rejected"] {
            assert_eq!(classify(&report(idle)), IndexState::Synced, "{idle}");
            let syncing = IndexReport { complete: false, ..report(idle) };
            assert_eq!(classify(&syncing), IndexState::Syncing, "{idle}");
            let off = IndexReport { enabled: false, ..report(idle) };
            assert_eq!(classify(&off), IndexState::Off, "{idle}");
        }
    }

    #[test]
    fn no_eta_is_absent_not_zero() {
        let r = IndexReport { eta_secs: 0, ..report("running") };
        let IndexState::Backfill { eta_secs, .. } = classify(&r) else { panic!() };
        assert_eq!(eta_secs, None);
    }

    #[test]
    fn progress_is_clamped() {
        let r = IndexReport { progress: 1.7, ..report("paused") };
        assert_eq!(classify(&r), IndexState::Paused { pass: Some(2), progress: 1.0 });
    }
}
