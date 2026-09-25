//! The status page while the node is still starting.
//!
//! Until the chain state exists there is no [`super::StatusSnapshot`] to
//! build, and a `-reindex-chainstate` keeps the node in that state for
//! hours. The metrics listener answers throughout from a startup status
//! server (`crate::metrics::serve_startup_http`), and this module is its
//! page: the same HTML, script and JSON envelope as the running node's,
//! filled from [`StartupSnapshot`] — the same source `getstartupinfo`
//! answers from — plus the version and network. It reads nothing else.
//!
//! The page is rendered by [`super::render::html`], so a tab opened during
//! startup carries every element the running node's view fills. When the
//! running node's listener takes the port over, the next refresh shows the
//! chain; the startup card hides itself because the running node's view
//! sets it hidden.

use super::render::{self, View, WAIT, bytes, duration, percent, thousands};
use crate::startup_progress::StartupSnapshot;

/// Startup phases that rebuild the node's databases from the block files
/// already on disk: `-reindex` (`clearing_db`, `reindex_scan`,
/// `reindex_connect`) and `-reindex-chainstate` (`reindex_chainstate`).
pub fn is_rebuild(phase: &str) -> bool {
    matches!(
        phase,
        "clearing_db" | "reindex_scan" | "reindex_connect" | "reindex_chainstate"
    )
}

/// The page's top line while starting.
pub fn label(phase: &str) -> &'static str {
    if is_rebuild(phase) {
        "rebuilding chainstate"
    } else {
        "starting"
    }
}

/// The cards the running node's view fills. The startup view hides each
/// one explicitly, so a tab that was showing the running node and polls
/// through a restart does not keep its last chain figures on screen.
pub(super) const NODE_CARDS: [&str; 5] = ["warnings", "chain", "wallets", "connect", "peers"];

/// Every key the startup card marks. The running node's view carries each
/// one blank and hidden ([`blank`]), so every marker on the page names a
/// key its view carries, whichever server rendered it.
const TEXT_KEYS: [&str; 6] = [
    "startup.message",
    "startup.note",
    "startup.progress",
    "startup.rate",
    "startup.elapsed",
    "startup.eta",
];
const SHOW_KEYS: [&str; 5] = [
    "startup",
    "startup.progress",
    "startup.bar",
    "startup.rate",
    "startup.eta",
];

/// The startup card's keys, blank and hidden: what the running node's view
/// carries for them.
pub(super) fn blank(v: &mut View) {
    for k in TEXT_KEYS {
        v.text.insert(k, String::new());
    }
    for k in SHOW_KEYS {
        v.show.insert(k, false);
    }
    v.width.insert("startup.bar", percent(0.0));
}

/// Build the startup view. `version` is the crate version, `network` the
/// status page's network label.
pub fn view(s: &StartupSnapshot, version: &str, network: &str) -> View {
    let mut v = View::default();
    blank(&mut v);
    let rebuild = is_rebuild(&s.phase);

    v.text.insert("phase.dot", "○".to_string());
    v.text.insert("phase.label", label(&s.phase).to_string());
    v.text.insert("network", network.to_string());
    v.text.insert("version", format!("v{version}"));
    v.text.insert("uptime", format!("up {}", duration(s.total_elapsed_secs)));
    v.state.insert("phase", WAIT);

    v.text.insert("startup.message", s.message.clone());
    let note = if rebuild {
        "Rebuilding from the block files already on disk; nothing is downloaded. \
         Wallets and the node's other services start when it finishes."
    } else {
        "The node is loading. Wallets and the node's other services start when it is ready."
    };
    v.text.insert("startup.note", note.to_string());

    // A snapshot download counts bytes; every other counting phase counts
    // blocks.
    let in_bytes = s.phase == "fast_start_download";
    let amount = |n: u64| {
        if in_bytes {
            bytes(n as usize)
        } else {
            format!("{} blocks", thousands(n))
        }
    };
    let target = s.target();
    let progress = if target > 0 {
        let share = s.current as f64 / target as f64;
        let of = if in_bytes { bytes(target as usize) } else { thousands(target) };
        let done = if in_bytes { bytes(s.current as usize) } else { thousands(s.current) };
        let unit = if in_bytes { "" } else { " blocks" };
        v.width.insert("startup.bar", percent(share));
        format!("{done} of {of}{unit} ({})", percent(share))
    } else if s.current > 0 {
        amount(s.current)
    } else {
        String::new()
    };
    v.show.insert("startup.progress", !progress.is_empty());
    v.show.insert("startup.bar", target > 0);
    v.text.insert("startup.progress", progress);

    if let Some(rate) = s.rate {
        let rate = if in_bytes {
            format!("{}/s", bytes(rate as usize))
        } else {
            format!("{rate:.1} blocks/s")
        };
        v.text.insert("startup.rate", rate);
        v.show.insert("startup.rate", true);
    }
    v.text.insert("startup.elapsed", duration(s.elapsed_secs));
    if let Some(eta) = s.eta_secs {
        v.text.insert("startup.eta", format!("about {} left", duration(eta)));
        v.show.insert("startup.eta", true);
    }

    v.show.insert("startup", true);
    for card in NODE_CARDS {
        v.show.insert(card, false);
    }
    v
}

/// The `/readyz` reason while starting: 503 `not ready: starting: <what the
/// node is doing>`.
pub fn not_ready_reason(s: &StartupSnapshot) -> String {
    format!("starting: {}", s.message)
}

/// The `/status.json` body while starting: the page's envelope and view,
/// with the `getstartupinfo` object in place of the running node's snapshot.
pub fn json(s: &StartupSnapshot, view: &View) -> String {
    render::encode_json(view, None, Some(s.startup_info()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rebuilding() -> StartupSnapshot {
        StartupSnapshot {
            phase: "reindex_chainstate".to_string(),
            message: "Replaying UTXO set".to_string(),
            current: 412_930,
            total: 967_870,
            stop_height: None,
            elapsed_secs: 3_725,
            total_elapsed_secs: 3_800,
            rate: Some(115.04),
            eta_secs: Some(4_800),
        }
    }

    #[test]
    fn the_startup_page_shows_the_rebuild_progress() {
        let v = view(&rebuilding(), "0.6.0-pre", "mainnet");
        assert_eq!(v.text["phase.label"], "rebuilding chainstate");
        assert_eq!(v.state["phase"], WAIT);
        assert_eq!(v.text["startup.message"], "Replaying UTXO set");
        assert_eq!(v.text["startup.progress"], "412,930 of 967,870 blocks (42.7%)");
        assert_eq!(v.width["startup.bar"], "42.7%");
        assert_eq!(v.text["startup.rate"], "115.0 blocks/s");
        assert_eq!(v.text["startup.elapsed"], "1h 02m");
        assert_eq!(v.text["startup.eta"], "about 1h 20m left");
        assert_eq!(v.text["uptime"], "up 1h 03m");
        assert_eq!(v.text["version"], "v0.6.0-pre");
        assert_eq!(v.text["network"], "mainnet");
        for key in ["startup", "startup.progress", "startup.bar", "startup.rate", "startup.eta"] {
            assert!(v.show[key], "{key} is hidden");
        }
        for card in NODE_CARDS {
            assert!(!v.show[card], "the {card} card shows during startup");
        }
        let page = render::html(&v);
        assert!(page.contains(">rebuilding chainstate<"), "the server render says it too");
        assert!(page.contains("412,930 of 967,870 blocks (42.7%)"));
        assert!(page.contains("data-s=\"chain\" hidden"), "the chain card is hidden in the first paint");
        assert!(!page.contains("data-s=\"startup\" hidden"), "the startup card is shown in the first paint");
    }

    #[test]
    fn other_startup_phases_say_starting_with_the_message() {
        for phase in ["opening_db", "chain_init", "checkblockindex", "fast_start_download"] {
            let s = StartupSnapshot {
                phase: phase.to_string(),
                message: "Initializing chain state...".to_string(),
                ..Default::default()
            };
            let v = view(&s, "0.6.0-pre", "signet");
            assert_eq!(v.text["phase.label"], "starting", "{phase}");
            assert_eq!(v.text["startup.message"], "Initializing chain state...", "{phase}");
            // Nothing counted yet: no progress row, no bar, no rate, no ETA.
            for key in ["startup.progress", "startup.bar", "startup.rate", "startup.eta"] {
                assert!(!v.show[key], "{phase}: {key} shows with nothing to show");
            }
            assert_eq!(not_ready_reason(&s), "starting: Initializing chain state...");
        }
        for phase in ["clearing_db", "reindex_scan", "reindex_connect", "reindex_chainstate"] {
            assert_eq!(label(phase), "rebuilding chainstate", "{phase}");
        }
    }

    /// `getstartupinfo`'s rule: the operator's goal is the stop target, not
    /// the file tip, so the bar fills towards `-stopatheight` when set.
    #[test]
    fn a_stop_height_is_the_progress_denominator() {
        let s = StartupSnapshot {
            stop_height: Some(500_000),
            current: 250_000,
            ..rebuilding()
        };
        let v = view(&s, "0.6.0-pre", "mainnet");
        assert_eq!(v.text["startup.progress"], "250,000 of 500,000 blocks (50.0%)");
        assert_eq!(v.width["startup.bar"], "50.0%");
        assert_eq!(s.startup_info()["percent"], 50.0);
    }

    /// A phase that counts without knowing its total (the block-file scan)
    /// shows the count and no bar.
    #[test]
    fn a_count_without_a_total_shows_no_bar() {
        let s = StartupSnapshot {
            phase: "reindex_scan".to_string(),
            message: "Scanning block files (phase 1/2)".to_string(),
            current: 12_345,
            ..Default::default()
        };
        let v = view(&s, "0.6.0-pre", "mainnet");
        assert_eq!(v.text["startup.progress"], "12,345 blocks");
        assert!(v.show["startup.progress"] && !v.show["startup.bar"]);
    }

    #[test]
    fn a_snapshot_download_counts_bytes() {
        let s = StartupSnapshot {
            phase: "fast_start_download".to_string(),
            message: "Downloading AssumeUTXO snapshot".to_string(),
            current: 2_500_000_000,
            total: 10_000_000_000,
            rate: Some(25_000_000.0),
            ..Default::default()
        };
        let v = view(&s, "0.6.0-pre", "mainnet");
        assert_eq!(v.text["startup.progress"], "2.50 GB of 10.00 GB (25.0%)");
        assert_eq!(v.text["startup.rate"], "25.0 MB/s");
        assert_eq!(v.text["phase.label"], "starting");
    }

    /// The JSON carries the page's envelope and view, and `getstartupinfo`'s
    /// object where the running node's snapshot would be.
    #[test]
    fn the_startup_json_carries_the_view_and_the_startup_info() {
        let s = rebuilding();
        let v = view(&s, "0.6.0-pre", "mainnet");
        let body: serde_json::Value = serde_json::from_str(&json(&s, &v)).unwrap();
        assert_eq!(body["view"], serde_json::to_value(&v).unwrap());
        assert!(body.get("snapshot").is_none(), "no snapshot while starting: {body}");
        assert_eq!(body["startup"], s.startup_info());
        assert_eq!(body["startup"]["started"], false);
        assert_eq!(body["startup"]["phase"], "reindex_chainstate");
        assert_eq!(body["startup"]["percent"], 42.7);
        assert_eq!(body["poll_ms"], render::POLL_MS);
        assert!(body["stability"].as_str().unwrap().starts_with("unstable"));
    }

    /// The message is the node's own text, but it still reaches the page as
    /// an escaped text node and the JSON as an escaped string.
    #[test]
    fn the_startup_message_is_escaped() {
        let s = StartupSnapshot {
            message: "<script>alert(1)</script>&".to_string(),
            ..rebuilding()
        };
        let v = view(&s, "0.6.0-pre", "mainnet");
        let page = render::html(&v);
        assert!(!page.contains("<script>alert"), "raw script tag in the page");
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;"));
        let body = json(&s, &v);
        assert!(!body.contains('<') && !body.contains('>'), "{body}");
    }
}
