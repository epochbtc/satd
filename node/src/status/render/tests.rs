use super::*;
use crate::status::indexes::IndexState;
use crate::status::*;

fn snapshot() -> StatusSnapshot {
    StatusSnapshot {
        version: "0.6.0-pre",
        network: "mainnet",
        uptime_secs: 3725,
        phase: Phase::BuildingIndexes,
        ready: true,
        warnings: vec![StatusWarning {
            id: "connect.retry".to_string(),
            severity: "warn",
            count: 3,
        }],
        unclean_shutdown: true,
        sync: SyncStatus {
            blocks: 912_345,
            headers: 912_350,
            tip_time: 1_780_000_000,
            header_time: 1_780_000_600,
            progress: 0.99991,
            blocks_per_sec: Some(1.25),
            headers_per_sec: Some(0.0),
            eta_secs: None,
        },
        assumeutxo: None,
        indexes: vec![
            NamedIndex {
                name: "address",
                state: IndexState::Synced,
            },
            NamedIndex {
                name: "silent_payments",
                state: IndexState::Backfill {
                    pass: None,
                    progress: 0.42,
                    cursor_height: 800_000,
                    snapshot_height: 912_000,
                    eta_secs: Some(3720),
                },
            },
        ],
        services: Services {
            esplora: ServiceState::Serving,
            electrum: ServiceState::Starting,
            wallets_ready: false,
        },
        connect: vec![Advertised::parse("electrum=ssl://umbrel.local:50012").unwrap()],
        peers: Peers {
            inbound: 2,
            outbound: 8,
            clients: vec![ClientCount {
                user_agent: "/Satoshi:29.0.0/".to_string(),
                count: 10,
            }],
        },
        mempool: MempoolStatus {
            transactions: 4321,
            bytes: 2_500_000,
            min_fee_rate_sat_vb: 1.0,
        },
        fees: Some(Fees {
            next_block: 12.4,
            three_blocks: 8.0,
            six_blocks: 2.25,
        }),
        latest_block: Some(LatestBlock {
            height: 912_345,
            hash: "00000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap(),
            time: 1_780_000_000,
            transactions: 3100,
            weight: 3_990_000,
            fees_sat: 4_120_000,
        }),
    }
}

/// Undo [`escape`], for reading values back out of the page.
fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// Every `data-t` element's text, as the page was rendered.
fn page_texts(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("data-t=\"") {
        rest = &rest[i + 8..];
        let key_end = rest.find('"').unwrap();
        let key = rest[..key_end].to_string();
        let open_end = rest.find('>').unwrap();
        let body = &rest[open_end + 1..];
        let close = body.find('<').unwrap();
        out.push((key, unescape(&body[..close])));
        rest = &body[close..];
    }
    out
}

/// The page script copies `view` into the page and formats nothing, so the
/// page as first served and the page after any refresh can only differ if
/// the view does. Check that every marked element in the HTML holds exactly
/// the view's value, and that no marker names a value the view lacks.
#[test]
fn status_json_and_html_render_the_same_snapshot() {
    let s = snapshot();
    let v = view(&s, 1_780_000_300);
    let page = html(&v);
    let texts = page_texts(&page);
    assert!(texts.len() > 20, "found only {} marked elements", texts.len());
    for (key, text) in &texts {
        let want = v.text.get(key.as_str()).unwrap_or_else(|| panic!("the page marks `{key}`, which the view does not carry"));
        assert_eq!(text, want, "`{key}`");
    }
    // And the JSON carries that same view.
    let body: serde_json::Value = serde_json::from_str(&json(&s, &v)).unwrap();
    assert_eq!(body["view"], serde_json::to_value(&v).unwrap());
    assert_eq!(body["snapshot"]["sync"]["blocks"], 912_345);
    // Each marked width, shown section and list is one the view has.
    for (attr, keys) in [
        ("data-w=\"", v.width.keys().copied().collect::<Vec<_>>()),
        ("data-s=\"", v.show.keys().copied().collect()),
        ("data-l=\"", v.lists.keys().copied().collect()),
        ("data-st=\"", v.state.keys().copied().collect()),
    ] {
        for part in page.split(attr).skip(1) {
            let key = &part[..part.find('"').unwrap()];
            assert!(keys.contains(&key), "the page marks {attr}{key}\" but the view has no such key");
        }
    }
}

#[test]
fn values_format_as_the_page_shows_them() {
    let v = view(&snapshot(), 1_780_000_300);
    assert_eq!(v.text["sync.blocks"], "912,345");
    assert_eq!(v.text["uptime"], "up 1h 02m");
    assert_eq!(v.text["block.age"], "5m 00s ago");
    assert_eq!(v.text["fees.1"], "12 sat/vB");
    assert_eq!(v.text["fees.6"], "2.2 sat/vB");
    assert_eq!(v.text["mempool.size"], "2.5 MB");
    assert_eq!(v.text["block.hash"], "00000000…aaaaaaaa");
    assert_eq!(v.state["phase"], WAIT);
    assert!(!v.show["sync"] && v.show["synced"] && v.show["warnings"]);
    let services = &v.lists["services"];
    assert_eq!(services[1].value, "serving");
    assert_eq!(services[3].value, "backfilling, 42.0%, about 1h 02m left");
    assert_eq!(v.lists["warnings"][0].label, "shutdown");
    assert_eq!(v.lists["warnings"][1].value, "warn (×3)");
}

/// A peer chooses its own user agent. It arrives as text in the page and as
/// an escaped string in the JSON, and in neither can it open a tag.
#[test]
fn status_escapes_peer_user_agent() {
    let hostile = "</code><script>alert(\"x\")</script><img src=x onerror=y>&'";
    let mut s = snapshot();
    s.peers.clients[0].user_agent = hostile.to_string();
    let v = view(&s, 1_780_000_300);

    let page = html(&v);
    assert!(!page.contains("<script>alert"), "raw script tag in the page");
    assert!(!page.contains("<img"), "raw img tag in the page");
    assert!(page.contains("&lt;/code&gt;&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"));
    // Exactly one <script>: the page's own.
    assert_eq!(page.matches("<script").count(), 1);

    let body = json(&s, &v);
    assert!(!body.contains('<') && !body.contains('>'), "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["view"]["lists"]["peers.clients"][0]["label"], hostile);
    assert_eq!(parsed["snapshot"]["peers"]["clients"][0]["user_agent"], hostile);
}

#[test]
fn the_script_never_writes_html() {
    for banned in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("] {
        assert!(!SCRIPT.contains(banned), "status.js uses {banned}");
    }
    assert!(SCRIPT.contains("textContent"));
}

#[test]
fn a_syncing_view_hides_the_synced_panels() {
    let mut s = snapshot();
    s.phase = Phase::SyncingBlocks;
    s.latest_block = None;
    s.fees = None;
    s.sync.eta_secs = Some(90_000);
    let v = view(&s, 0);
    assert!(v.show["sync"] && !v.show["synced"] && !v.show["block"] && !v.show["fees"]);
    assert_eq!(v.text["sync.eta"], "about 1d 01h left");
    assert_eq!(v.text["phase.label"], "syncing blocks");
    let page = html(&v);
    assert!(page.contains("data-s=\"synced\" hidden"), "server render hides it too");
}
