//! `/status` and `/status.json`, from one [`View`].
//!
//! Every string the page shows is formatted here, once. The HTML page
//! carries the view's values in elements marked `data-t` (text), `data-w`
//! (a bar's width), `data-s` (shown or hidden), `data-state` (a tone) and
//! `data-l` (a list). `/status.json` carries the same view, and
//! `/status.js` copies each value into the element with the matching
//! marker using `textContent`, never `innerHTML`. `data-st` names the
//! element whose `data-state` a tone from the view sets. The script formats
//! nothing, so the first paint and every refresh cannot disagree.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use super::indexes::IndexState;
use super::{Phase, ServiceState, StatusSnapshot};

/// A tone, rendered as `data-state` and styled by the page.
pub type Tone = &'static str;
pub const OK: Tone = "ok";
pub const WAIT: Tone = "wait";
pub const BAD: Tone = "bad";
pub const OFF: Tone = "off";

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Item {
    pub label: String,
    pub value: String,
    pub state: Tone,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct View {
    pub text: BTreeMap<&'static str, String>,
    pub width: BTreeMap<&'static str, String>,
    pub show: BTreeMap<&'static str, bool>,
    pub state: BTreeMap<&'static str, Tone>,
    pub lists: BTreeMap<&'static str, Vec<Item>>,
}

/// How long the page trusts a view before marking it stale: two missed
/// 5-second polls, plus slack.
pub const STALE_AFTER_MS: u64 = 12_000;
pub const POLL_MS: u64 = 5_000;

#[derive(Serialize)]
struct JsonBody<'a> {
    /// Said in the response itself, as `STABILITY_POLICY.md` asks of a
    /// Tier 3 surface.
    stability: &'static str,
    poll_ms: u64,
    stale_after_ms: u64,
    view: &'a View,
    /// The running node's snapshot. Absent while the node starts.
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot: Option<&'a StatusSnapshot>,
    /// `getstartupinfo`'s object, while the node starts ([`super::startup`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    startup: Option<serde_json::Value>,
}

/// The `/status.json` body. `<`, `>` and `&` are written as `\u` escapes, so
/// no peer-supplied string can close a tag even if the body were ever
/// mistaken for HTML.
pub fn json(snapshot: &StatusSnapshot, view: &View) -> String {
    encode_json(view, Some(snapshot), None)
}

/// The envelope both `/status.json` bodies share, escaped as [`json`] says.
pub(super) fn encode_json(
    view: &View,
    snapshot: Option<&StatusSnapshot>,
    startup: Option<serde_json::Value>,
) -> String {
    let body = serde_json::to_string(&JsonBody {
        stability: "unstable: internal to the status page; any field may change in any release",
        poll_ms: POLL_MS,
        stale_after_ms: STALE_AFTER_MS,
        view,
        snapshot,
        startup,
    })
    .unwrap_or_else(|_| "{}".to_string());
    // Outside strings, JSON never contains these characters, so replacing
    // every occurrence only ever rewrites string contents.
    body.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

pub(super) fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn duration(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m {:02}s", secs / 60, secs % 60),
        3600..86_400 => format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d {:02}h", secs / 86_400, (secs % 86_400) / 3600),
    }
}

pub(super) fn bytes(n: usize) -> String {
    let n = n as f64;
    if n < 1e3 {
        format!("{n} B")
    } else if n < 1e6 {
        format!("{:.1} kB", n / 1e3)
    } else if n < 1e9 {
        format!("{:.1} MB", n / 1e6)
    } else {
        format!("{:.2} GB", n / 1e9)
    }
}

pub(super) fn percent(f: f64) -> String {
    format!("{:.1}%", (f * 100.0).clamp(0.0, 100.0))
}

fn fee_rate(sat_vb: f64) -> String {
    if sat_vb < 10.0 {
        format!("{sat_vb:.1} sat/vB")
    } else {
        format!("{sat_vb:.0} sat/vB")
    }
}

fn index_label(name: &str) -> &'static str {
    match name {
        "address" => "Address index",
        "silent_payments" => "Silent-payment index",
        "block_filters" => "Block filter index",
        _ => "Index",
    }
}

fn index_item(name: &str, state: &IndexState) -> Item {
    let (value, tone) = match state {
        IndexState::Off => ("off".to_string(), OFF),
        IndexState::Synced => ("synced".to_string(), OK),
        IndexState::Syncing => ("building with the chain".to_string(), WAIT),
        IndexState::Backfill {
            pass,
            progress,
            eta_secs,
            ..
        } => {
            let pass = pass.map(|p| format!("pass {p} of 2, ")).unwrap_or_default();
            let eta = eta_secs.map(|s| format!(", about {} left", duration(s))).unwrap_or_default();
            (format!("backfilling, {pass}{}{eta}", percent(*progress)), WAIT)
        }
        IndexState::Paused { progress, .. } => {
            (format!("backfill paused at {}", percent(*progress)), WAIT)
        }
        IndexState::Failed => ("backfill failed; see getsatdindexinfo".to_string(), BAD),
    };
    Item {
        label: index_label(name).to_string(),
        value,
        state: tone,
    }
}

fn service_item(label: &str, s: ServiceState) -> Item {
    let (value, tone) = match s {
        ServiceState::Serving => ("serving", OK),
        ServiceState::Starting => ("waiting to start", WAIT),
        ServiceState::Off => ("off", OFF),
    };
    Item {
        label: label.to_string(),
        value: value.to_string(),
        state: tone,
    }
}

/// Build the view. `now` is the node clock, for block ages.
pub fn view(s: &StatusSnapshot, now: u64) -> View {
    let mut v = View::default();
    let mut text = |k: &'static str, val: String| {
        v.text.insert(k, val);
    };

    let (dot, label, tone) = match s.phase {
        Phase::Stalled => ("✕", "stalled", BAD),
        Phase::SyncingHeaders => ("○", "syncing headers", WAIT),
        Phase::SyncingBlocks => ("○", "syncing blocks", WAIT),
        Phase::BackgroundValidation => ("●", "validating history", WAIT),
        Phase::BuildingIndexes => ("●", "building indexes", WAIT),
        Phase::Ready => ("●", "ready", OK),
    };
    text("phase.dot", dot.to_string());
    text("phase.label", label.to_string());
    text("network", s.network.to_string());
    text("version", format!("v{}", s.version));
    text("uptime", format!("up {}", duration(s.uptime_secs)));

    let note = match s.phase {
        Phase::Stalled => {
            "The node cannot connect the next block, so the chain is not advancing. \
             Its log says why."
        }
        Phase::SyncingHeaders => {
            "Downloading block headers. Until they reach the present, the block count \
             is measured against the headers known so far."
        }
        Phase::SyncingBlocks => "Downloading and validating blocks.",
        Phase::BackgroundValidation => {
            "Serving from an AssumeUTXO snapshot while the history behind it is \
             validated."
        }
        Phase::BuildingIndexes => {
            "At the chain tip. An index is still being built, so answers that read \
             through it are incomplete."
        }
        Phase::Ready => "At the chain tip, with every enabled index complete.",
    };
    text("phase.note", note.to_string());

    text("sync.blocks", thousands(u64::from(s.sync.blocks)));
    text("sync.headers", thousands(u64::from(s.sync.headers)));
    text("sync.percent", percent(s.sync.progress));
    let rates = match (s.sync.blocks_per_sec, s.sync.headers_per_sec) {
        (Some(b), Some(h)) => format!("{b:.1} blocks/s, {h:.0} headers/s"),
        _ => "measuring…".to_string(),
    };
    text("sync.rates", rates);
    text(
        "sync.eta",
        s.sync.eta_secs.map(|e| format!("about {} left", duration(e))).unwrap_or_default(),
    );

    // Sections that are absent still carry every key, empty, so a section
    // that appears on a later refresh has every element filled.
    let au = s.assumeutxo.as_ref();
    text("au.height", au.map(|a| thousands(u64::from(a.background_height))).unwrap_or_default());
    text("au.snapshot", au.map(|a| thousands(u64::from(a.snapshot_height))).unwrap_or_default());
    text("au.percent", au.map(|a| percent(a.background_progress)).unwrap_or_default());

    let wallets = if s.services.wallets_ready {
        ("Wallets can connect and get complete answers.", OK)
    } else if matches!(s.phase, Phase::Stalled | Phase::SyncingHeaders | Phase::SyncingBlocks) {
        ("Wallets can connect, but balances are incomplete until the sync finishes.", WAIT)
    } else {
        ("Wallet answers are incomplete until the address index is complete and a wallet server is serving.", WAIT)
    };
    text("wallets", wallets.0.to_string());

    let b = s.latest_block.as_ref();
    text("block.height", b.map(|b| thousands(u64::from(b.height))).unwrap_or_default());
    text(
        "block.age",
        b.map(|b| format!("{} ago", duration(now.saturating_sub(u64::from(b.time)))))
            .unwrap_or_default(),
    );
    text("block.txs", b.map(|b| thousands(b.transactions as u64)).unwrap_or_default());
    text("block.fees", b.map(|b| format!("{} sat", thousands(b.fees_sat))).unwrap_or_default());
    text(
        "block.hash",
        b.map(|b| {
            let hash = b.hash.to_string();
            format!("{}…{}", &hash[..8], &hash[hash.len() - 8..])
        })
        .unwrap_or_default(),
    );

    text("mempool.txs", thousands(s.mempool.transactions as u64));
    text("mempool.size", bytes(s.mempool.bytes));
    text("mempool.minfee", fee_rate(s.mempool.min_fee_rate_sat_vb));
    let f = s.fees.as_ref();
    text("fees.1", f.map(|f| fee_rate(f.next_block)).unwrap_or_default());
    text("fees.3", f.map(|f| fee_rate(f.three_blocks)).unwrap_or_default());
    text("fees.6", f.map(|f| fee_rate(f.six_blocks)).unwrap_or_default());

    let total = s.peers.inbound + s.peers.outbound;
    text(
        "peers.total",
        format!("{total} ({} outbound, {} inbound)", s.peers.outbound, s.peers.inbound),
    );

    v.width.insert("sync.bar", percent(s.sync.progress));
    v.width.insert(
        "au.bar",
        percent(s.assumeutxo.as_ref().map(|a| a.background_progress).unwrap_or(0.0)),
    );

    let syncing = matches!(s.phase, Phase::Stalled | Phase::SyncingHeaders | Phase::SyncingBlocks);
    v.show.insert("sync", syncing);
    v.show.insert("synced", !syncing);
    v.show.insert("au", s.assumeutxo.is_some());
    v.show.insert(
        "au.rejected",
        s.assumeutxo.as_ref().is_some_and(|a| a.rejected),
    );
    v.show.insert("block", s.latest_block.is_some());
    v.show.insert("fees", s.fees.is_some());
    v.show.insert("warnings", !s.warnings.is_empty() || s.unclean_shutdown);
    v.show.insert("connect", !s.connect.is_empty());
    v.show.insert("eta", s.sync.eta_secs.is_some());
    // The cards that are always on for a running node. They carry `data-s`
    // only so the startup view can hide them.
    for card in ["chain", "wallets", "peers"] {
        v.show.insert(card, true);
    }
    super::startup::blank(&mut v);

    v.state.insert("phase", tone);
    v.state.insert("wallets", wallets.1);

    let mut warnings: Vec<Item> = Vec::new();
    if s.unclean_shutdown {
        warnings.push(Item {
            label: "shutdown".to_string(),
            value: "the previous run did not shut down cleanly".to_string(),
            state: WAIT,
        });
    }
    warnings.extend(s.warnings.iter().map(|w| Item {
        label: w.id.clone(),
        value: if w.count > 1 {
            format!("{} (×{})", w.severity, w.count)
        } else {
            w.severity.to_string()
        },
        state: if w.severity == "error" { BAD } else { WAIT },
    }));
    v.lists.insert("warnings", warnings);

    let mut services = vec![
        service_item("Electrum", s.services.electrum),
        service_item("Esplora", s.services.esplora),
    ];
    services.extend(s.indexes.iter().map(|i| index_item(i.name, &i.state)));
    v.lists.insert("services", services);

    v.lists.insert(
        "connect",
        s.connect
            .iter()
            .map(|a| Item {
                label: a.surface.label().to_string(),
                value: a.url.clone(),
                state: OK,
            })
            .collect(),
    );
    v.lists.insert(
        "peers.clients",
        s.peers
            .clients
            .iter()
            .map(|c| Item {
                label: c.user_agent.clone(),
                value: c.count.to_string(),
                state: OK,
            })
            .collect(),
    );
    v
}

/// Escape text for an HTML text node or a double-quoted attribute.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

struct Page<'a> {
    v: &'a View,
    out: String,
}

impl Page<'_> {
    fn raw(&mut self, s: &str) {
        self.out.push_str(s);
    }
    /// `<tag data-t="key">value</tag>`
    fn t(&mut self, tag: &str, key: &'static str) {
        let val = self.v.text.get(key).map(String::as_str).unwrap_or("");
        let _ = write!(self.out, "<{tag} data-t=\"{key}\">{}</{tag}>", escape(val));
    }
    /// The opening tag of a section shown or hidden by `data-s`.
    fn section(&mut self, tag: &str, key: &'static str, class: &str) {
        let hidden = if self.v.show.get(key).copied().unwrap_or(false) { "" } else { " hidden" };
        let _ = write!(self.out, "<{tag} class=\"{class}\" data-s=\"{key}\"{hidden}>");
    }
    fn bar(&mut self, key: &'static str) {
        let w = self.v.width.get(key).map(String::as_str).unwrap_or("0.0%");
        let _ = write!(
            self.out,
            "<div class=\"bar\"><i data-w=\"{key}\" style=\"width:{}\"></i></div>",
            escape(w)
        );
    }
    fn list(&mut self, key: &'static str) {
        let _ = write!(self.out, "<ul class=\"items\" data-l=\"{key}\">");
        for item in self.v.lists.get(key).map(Vec::as_slice).unwrap_or(&[]) {
            let _ = write!(
                self.out,
                "<li data-state=\"{}\"><span>{}</span><code>{}</code></li>",
                item.state,
                escape(&item.label),
                escape(&item.value)
            );
        }
        self.raw("</ul>");
    }
}

const STYLE: &str = r#"
:root{--bg:#f7f7f5;--fg:#1c1c1a;--mute:#6b6b66;--card:#fff;--line:#e3e3de;--ok:#1f8a4c;--wait:#b7791f;--bad:#c53030;--bar:#e9e9e4}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ececea;--mute:#9a9a94;--card:#1d1d1b;--line:#2e2e2b;--ok:#48bb78;--wait:#ecc94b;--bad:#fc8181;--bar:#2e2e2b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:52rem;margin:0 auto;padding:1.25rem 1rem 3rem}
header{display:flex;flex-wrap:wrap;align-items:baseline;gap:.35rem .75rem;margin-bottom:1rem}
header h1{font-size:1.35rem;margin:0}
.mute{color:var(--mute)}
.phase{font-weight:600}
[data-state=ok]{color:var(--ok)}[data-state=wait]{color:var(--wait)}[data-state=bad]{color:var(--bad)}[data-state=off]{color:var(--mute)}
.card{background:var(--card);border:1px solid var(--line);border-radius:.6rem;padding:.9rem 1rem;margin:.75rem 0}
.card h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mute);margin:0 0 .5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:0 1rem}
.kv{display:flex;justify-content:space-between;gap:1rem;padding:.2rem 0;border-bottom:1px dashed var(--line)}
.kv:last-child{border-bottom:0}
.bar{height:.6rem;background:var(--bar);border-radius:.3rem;overflow:hidden;margin:.5rem 0}
.bar i{display:block;height:100%;background:var(--ok)}
.items{list-style:none;margin:0;padding:0}
.items li{display:flex;justify-content:space-between;gap:1rem;padding:.25rem 0;border-bottom:1px dashed var(--line);overflow-wrap:anywhere}
.items li:last-child{border-bottom:0}
.items li span{color:var(--fg)}
code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;user-select:all}
footer{margin-top:1.5rem;font-size:.85rem}
"#;

/// The `/status` page, complete without JavaScript.
pub fn html(v: &View) -> String {
    let mut p = Page {
        v,
        out: String::with_capacity(8192),
    };
    p.raw("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    p.raw("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    p.raw("<meta name=\"robots\" content=\"noindex\"><title>satd status</title><style>");
    p.raw(STYLE);
    p.raw("</style></head><body><main>");

    // Header.
    p.raw("<header><h1>satd</h1>");
    let tone = v.state.get("phase").copied().unwrap_or(WAIT);
    let _ = write!(p.out, "<span class=\"phase\" data-state=\"{tone}\" data-st=\"phase\" id=\"phase\">");
    p.t("span", "phase.dot");
    p.raw(" ");
    p.t("span", "phase.label");
    p.raw("</span>");
    p.raw("<span class=\"mute\">");
    p.t("span", "network");
    p.raw(" · ");
    p.t("span", "version");
    p.raw(" · ");
    p.t("span", "uptime");
    p.raw("</span></header>");

    // While the node starts: what it is doing, and how far along it is.
    // Hidden once the running node serves the page.
    p.section("section", "startup", "card");
    p.raw("<h2>Startup</h2>");
    p.t("p", "startup.message");
    p.raw("<p class=\"mute\" data-t=\"startup.note\">");
    let note = v.text.get("startup.note").map(String::as_str).unwrap_or("");
    p.raw(&escape(note));
    p.raw("</p>");
    p.section("div", "startup.progress", "");
    p.raw("<div class=\"kv\"><span>Progress</span>");
    p.t("span", "startup.progress");
    p.raw("</div>");
    p.section("div", "startup.bar", "");
    p.bar("startup.bar");
    p.raw("</div>");
    p.section("div", "startup.rate", "kv");
    p.raw("<span>Rate</span>");
    p.t("span", "startup.rate");
    p.raw("</div></div>");
    p.raw("<div class=\"kv\"><span>Elapsed</span>");
    p.t("span", "startup.elapsed");
    p.raw("</div>");
    p.section("div", "startup.eta", "kv");
    p.raw("<span>Remaining</span>");
    p.t("span", "startup.eta");
    p.raw("</div></section>");

    p.section("section", "warnings", "card");
    p.raw("<h2>Warnings</h2>");
    p.list("warnings");
    p.raw("</section>");

    // Where the node is.
    p.section("section", "chain", "card");
    p.raw("<h2>Chain</h2>");
    p.t("p", "phase.note");
    p.section("div", "sync", "");
    p.raw("<div class=\"kv\"><span>Blocks</span><span>");
    p.t("span", "sync.blocks");
    p.raw(" of ");
    p.t("span", "sync.headers");
    p.raw("</span></div>");
    p.bar("sync.bar");
    p.raw("<div class=\"kv\"><span>Progress, by work</span>");
    p.t("span", "sync.percent");
    p.raw("</div><div class=\"kv\"><span>Rate</span>");
    p.t("span", "sync.rates");
    p.raw("</div>");
    p.section("div", "eta", "kv");
    p.raw("<span>Remaining</span>");
    p.t("span", "sync.eta");
    p.raw("</div></div>");
    p.section("div", "synced", "grid");
    p.raw("<div>");
    p.raw("<div class=\"kv\"><span>Height</span>");
    p.t("span", "sync.blocks");
    p.raw("</div>");
    p.section("div", "block", "");
    p.raw("<div class=\"kv\"><span>Latest block</span>");
    p.t("span", "block.age");
    p.raw("</div><div class=\"kv\"><span>Transactions</span>");
    p.t("span", "block.txs");
    p.raw("</div><div class=\"kv\"><span>Fees</span>");
    p.t("span", "block.fees");
    p.raw("</div><div class=\"kv\"><span>Hash</span>");
    p.t("code", "block.hash");
    p.raw("</div></div></div><div>");
    p.raw("<div class=\"kv\"><span>Mempool</span><span>");
    p.t("span", "mempool.txs");
    p.raw(" txs, ");
    p.t("span", "mempool.size");
    p.raw("</span></div><div class=\"kv\"><span>Minimum fee</span>");
    p.t("span", "mempool.minfee");
    p.raw("</div>");
    p.section("div", "fees", "");
    p.raw("<div class=\"kv\"><span>Next block</span>");
    p.t("span", "fees.1");
    p.raw("</div><div class=\"kv\"><span>Within 3 blocks</span>");
    p.t("span", "fees.3");
    p.raw("</div><div class=\"kv\"><span>Within 6 blocks</span>");
    p.t("span", "fees.6");
    p.raw("</div></div></div></div>");
    p.section("div", "au", "");
    p.raw("<h2>AssumeUTXO</h2><div class=\"kv\"><span>History validated</span><span>");
    p.t("span", "au.height");
    p.raw(" of ");
    p.t("span", "au.snapshot");
    p.raw(" (");
    p.t("span", "au.percent");
    p.raw(")</span></div>");
    p.bar("au.bar");
    p.section("p", "au.rejected", "");
    p.raw("<strong data-state=\"bad\">Background validation proved this snapshot invalid. \
           Do not trust this node's answers; reindex without the snapshot.</strong></p></div>");
    p.raw("</section>");

    // What a wallet can use.
    p.section("section", "wallets", "card");
    p.raw("<h2>Wallets</h2>");
    let wtone = v.state.get("wallets").copied().unwrap_or(WAIT);
    let _ = write!(
        p.out,
        "<p data-state=\"{wtone}\" data-st=\"wallets\" data-t=\"wallets\">{}</p>",
        escape(v.text.get("wallets").map(String::as_str).unwrap_or(""))
    );
    p.list("services");
    p.raw("</section>");

    p.section("section", "connect", "card");
    p.raw("<h2>Connect</h2>");
    p.list("connect");
    p.raw("</section>");

    p.section("section", "peers", "card");
    p.raw("<h2>Peers</h2><div class=\"kv\"><span>Connected</span>");
    p.t("span", "peers.total");
    p.raw("</div>");
    p.list("peers.clients");
    p.raw("</section>");

    p.raw("<footer class=\"mute\"><span id=\"freshness\">Reload to update.</span></footer>");
    p.raw("</main><script src=\"status.js\" defer></script></body></html>");
    p.out
}

/// The page script, served as `/status.js`.
pub const SCRIPT: &str = include_str!("status.js");

#[cfg(test)]
mod tests;
