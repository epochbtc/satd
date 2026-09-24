use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Bar, BarChart, Block, Borders, Paragraph, Sparkline};

use crate::state::AppState;
use crate::ui::{
    format_bytes, format_btc, format_count3, format_duration, format_hash, format_hashrate,
    format_num, format_vsize_edge, log_bar, peer_table, render_loading_panel,
};

pub fn draw(f: &mut Frame, state: &AppState) {
    let size = f.area();

    let constraints = vec![
        Constraint::Length(1),  // title
        Constraint::Length(9),  // chain + latest block
        Constraint::Length(12), // mempool + fee estimates (4 text rows, a 4-row chart)
        Constraint::Length(11), // utxo + network (3 text rows, a 4-row chart)
        Constraint::Min(5),     // peers
        Constraint::Length(1),  // services status (addr-index, sp-index, esplora, electrum)
        Constraint::Length(1),  // footer
    ];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(size);

    // Title bar with health dot.
    let uptime_str = state.uptime_secs
        .map(|s| format!(" up {} ", format_duration(s)))
        .unwrap_or_default();
    let (dot_glyph, dot_color, health_label) = if state.is_healthy() {
        ("● ", Color::Green, "ready")
    } else if state.stale || !state.connected {
        ("✕ ", Color::Red, "stale")
    } else {
        ("○ ", Color::Yellow, "syncing")
    };
    let title = Line::from(vec![
        Span::styled(" satd ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!(" {} ", state.chain_name),
            Style::default().fg(Color::White),
        ),
        Span::styled(dot_glyph, Style::default().fg(dot_color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{} ", health_label), Style::default().fg(dot_color)),
        Span::styled(state.version_line(), Style::default().fg(Color::DarkGray)),
        Span::styled(uptime_str, Style::default().fg(Color::DarkGray)),
        // A method that is failing while the connection is fine shows up
        // nowhere else: the health dot tracks the connection, and the panel
        // fed by that method just keeps its last value.
        Span::styled(
            state.rpc_failure_line().unwrap_or_default(),
            Style::default().fg(Color::Red),
        ),
    ]);
    f.render_widget(Paragraph::new(title), chunks[0]);

    // Row 1: Chain + Latest Block
    draw_top_row(f, chunks[1], state);

    // Row 2: Mempool + Fee Estimates
    draw_middle_row(f, chunks[2], state);

    // Row 3: UTXO + Network
    draw_bottom_row(f, chunks[3], state);

    // Peers
    let peer_title = format!("Peers ({} connected)", state.connections);
    let table = peer_table(&state.peers, None, &state.peer_dl_rates, state.selected_peer, &peer_title);
    f.render_widget(table, chunks[4]);

    // Services row — always visible. Shows addr-index, Esplora and
    // Electrum status side-by-side, plus the silent-payment index when
    // it is enabled. When a backfill is running / paused / failed, that
    // index's column shows backfill progress instead of the steady-state
    // synced/syncing label.
    f.render_widget(Paragraph::new(services_line(state)), chunks[5]);

    let footer_idx = 6;

    // Footer — keybindings plus an unclean-shutdown hint if applicable.
    let mut spans = vec![
        Span::styled("q", Style::default().fg(Color::White)),
        Span::styled(": quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled("h", Style::default().fg(Color::White)),
        Span::styled(": help  ", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::White)),
        Span::styled(": reorgs  ", Style::default().fg(Color::DarkGray)),
        Span::styled("1/2/3/4", Style::default().fg(Color::White)),
        Span::styled(": view  ", Style::default().fg(Color::DarkGray)),
        Span::raw("\u{2191}\u{2193}"),
        Span::styled(": peers", Style::default().fg(Color::DarkGray)),
    ];
    if state.last_shutdown.as_deref() == Some("dirty") {
        spans.push(Span::styled(
            "   ⚠ previous shutdown was unclean",
            Style::default().fg(Color::Yellow),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), chunks[footer_idx]);
}

/// Single-line services row. Columns separated by two spaces:
/// `addr-idx <state>`, `sp-idx <state>` (only when the silent-payment
/// index is enabled), `esplora <state>`, `electrum <state>`.
///
/// `<state>` for addr-idx is the backfill summary when one is active
/// (running / paused / failed), the live `synced`/`syncing`/`off`/`-`
/// label otherwise. For listeners it is the bind address when bound,
/// `off` when explicitly not bound, `-` (dim) when status is unknown
/// (RPC not yet returned, older satd build, transient error). The
/// Electrum TLS bind, when present, follows the plain bind in
/// parentheses.
fn services_line(state: &AppState) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    addr_index_spans(&mut spans, state);
    // Silent-payment column only when the index is on (or mid-backfill).
    // Nodes not using the feature keep the original three-column row
    // rather than gaining a permanently dim placeholder, which also keeps
    // the line from overflowing narrow terminals for no benefit.
    if let Some(sp) = state.sp_index.as_ref().filter(|s| s.is_visible()) {
        spans.push(Span::raw("  "));
        sp_index_spans(&mut spans, sp);
    }
    spans.push(Span::raw("  "));
    listener_spans(&mut spans, "esplora", &state.server_status.esplora, None);
    spans.push(Span::raw("  "));
    listener_spans(
        &mut spans,
        "electrum",
        &state.server_status.electrum,
        Some(&state.server_status.electrum_tls),
    );
    Line::from(spans)
}

/// `sp-idx <state>` — the BIP 352 tweak index.
///
/// Backfill detail while one is running / paused / failed, otherwise the
/// steady `synced` / `syncing` label. There is no `off` arm: a disabled
/// index means the column is not rendered at all.
///
/// The backfill is a single pass (unlike the address index's two), so
/// there is no pass counter. The percentage is the daemon's
/// walk-start-based `progress_ratio`, never cursor/snapshot — that
/// division measures from genesis and overstates progress on mainnet
/// from the first block of the run. A daemon too old to send the ratio
/// gets the raw counts with no percentage at all: no number beats a
/// wrong one.
fn sp_index_spans(spans: &mut Vec<Span<'static>>, sp: &crate::state::SpIndexProgress) {
    let label = "sp-idx";
    if sp.backfill_is_visible() {
        let pct = sp
            .progress_ratio()
            .map(|r| format!("{:.1}% ", r * 100.0))
            .unwrap_or_default();
        let cursor = format_num(sp.cursor_height as u64);
        let snapshot = format_num(sp.snapshot_height as u64);
        match sp.state.as_str() {
            "running" => {
                let eta = if sp.estimated_remaining_seconds > 0 {
                    format!("  ETA {}", format_duration(sp.estimated_remaining_seconds))
                } else {
                    String::new()
                };
                spans.push(dot(Color::Green));
                spans.push(Span::styled(label, Style::default().fg(Color::White)));
                spans.push(Span::styled(
                    format!(" backfill {}({}/{}){}", pct, cursor, snapshot, eta),
                    Style::default().fg(Color::Gray),
                ));
            }
            "paused" => {
                spans.push(dot(Color::Yellow));
                spans.push(Span::styled(label, Style::default().fg(Color::White)));
                spans.push(Span::styled(
                    format!(" backfill paused {pct}— resumeindex silentpayment"),
                    Style::default().fg(Color::Yellow),
                ));
            }
            "failed" => {
                let err = sp.last_error.as_deref().unwrap_or("(no error)");
                let err_short: String = err.chars().take(60).collect();
                spans.push(dot(Color::Red));
                spans.push(Span::styled(label, Style::default().fg(Color::White)));
                spans.push(Span::styled(
                    format!(" backfill FAILED — {err_short}"),
                    Style::default().fg(Color::LightRed),
                ));
            }
            _ => {}
        }
        return;
    }
    if sp.synced {
        spans.push(dot(Color::Green));
        spans.push(Span::styled(label, Style::default().fg(Color::White)));
        spans.push(Span::styled(" synced", Style::default().fg(Color::Gray)));
    } else {
        // Enabled but not caught up: fresh sync in progress, or a
        // backfill is still owed before the tweak-serving surfaces
        // return data.
        spans.push(dot(Color::Yellow));
        spans.push(Span::styled(label, Style::default().fg(Color::White)));
        spans.push(Span::styled(" syncing", Style::default().fg(Color::Yellow)));
    }
}

fn addr_index_spans(spans: &mut Vec<Span<'static>>, state: &AppState) {
    let label = "addr-idx";
    if let Some(bf) = state.backfill.as_ref().filter(|b| b.is_visible()) {
        let pct = bf.progress_ratio() * 100.0;
        let cursor = format_num(bf.cursor_height as u64);
        let snapshot = format_num(bf.snapshot_height as u64);
        match bf.state.as_str() {
            "running" => {
                let eta = if bf.estimated_remaining_seconds > 0 {
                    format!("  ETA {}", format_duration(bf.estimated_remaining_seconds))
                } else {
                    String::new()
                };
                spans.push(dot(Color::Green));
                spans.push(Span::styled(label, Style::default().fg(Color::White)));
                spans.push(Span::styled(
                    format!(
                        " backfill pass {}/2 {:.1}% ({}/{}){}",
                        bf.pass.clamp(1, 2),
                        pct,
                        cursor,
                        snapshot,
                        eta,
                    ),
                    Style::default().fg(Color::Gray),
                ));
            }
            "paused" => {
                spans.push(dot(Color::Yellow));
                spans.push(Span::styled(label, Style::default().fg(Color::White)));
                spans.push(Span::styled(
                    format!(
                        " backfill paused pass {}/2 {:.1}% — resumeindex address",
                        bf.pass.clamp(1, 2),
                        pct,
                    ),
                    Style::default().fg(Color::Yellow),
                ));
            }
            "failed" => {
                let err = bf.last_error.as_deref().unwrap_or("(no error)");
                let err_short: String = err.chars().take(60).collect();
                spans.push(dot(Color::Red));
                spans.push(Span::styled(label, Style::default().fg(Color::White)));
                spans.push(Span::styled(
                    format!(" backfill FAILED — {}", err_short),
                    Style::default().fg(Color::LightRed),
                ));
            }
            _ => {}
        }
        return;
    }
    match &state.server_status.addressindex {
        crate::state::ListenerView::Unknown => {
            // No status from satd yet (first poll, older satd, transient
            // RPC error). Stay neutral — don't claim disabled.
            spans.push(dot(Color::DarkGray));
            spans.push(Span::styled(label, Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(" -", Style::default().fg(Color::DarkGray)));
        }
        crate::state::ListenerView::NotBound => {
            // Should not occur for the addressindex variant — it always
            // emits a `Bound(_)` view since the daemon always reports
            // both flags. Render as unknown if we ever see it.
            spans.push(dot(Color::DarkGray));
            spans.push(Span::styled(label, Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(" -", Style::default().fg(Color::DarkGray)));
        }
        crate::state::ListenerView::Bound(ai) if !ai.enabled => {
            spans.push(dot(Color::DarkGray));
            spans.push(Span::styled(label, Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(" off", Style::default().fg(Color::DarkGray)));
        }
        crate::state::ListenerView::Bound(ai) if ai.complete => {
            spans.push(dot(Color::Green));
            spans.push(Span::styled(label, Style::default().fg(Color::White)));
            spans.push(Span::styled(" synced", Style::default().fg(Color::Gray)));
        }
        crate::state::ListenerView::Bound(_) => {
            // Enabled but the on-disk completeness marker isn't set —
            // fresh sync still in progress, or a backfill is needed
            // before Electrum / Esplora can bind.
            spans.push(dot(Color::Yellow));
            spans.push(Span::styled(label, Style::default().fg(Color::White)));
            spans.push(Span::styled(
                " syncing",
                Style::default().fg(Color::Yellow),
            ));
        }
    }
}

fn listener_spans(
    spans: &mut Vec<Span<'static>>,
    label: &'static str,
    view: &crate::state::ListenerView<crate::state::ListenerStatus>,
    tls_view: Option<&crate::state::ListenerView<crate::state::ListenerStatus>>,
) {
    use crate::state::ListenerView::*;
    match view {
        Unknown => {
            spans.push(dot(Color::DarkGray));
            spans.push(Span::styled(label, Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(" -", Style::default().fg(Color::DarkGray)));
        }
        NotBound => {
            spans.push(dot(Color::DarkGray));
            spans.push(Span::styled(label, Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(" off", Style::default().fg(Color::DarkGray)));
        }
        Bound(l) => {
            spans.push(dot(Color::Green));
            spans.push(Span::styled(label, Style::default().fg(Color::White)));
            spans.push(Span::styled(
                format!(" {}", l.bind),
                Style::default().fg(Color::Gray),
            ));
            if let Some(Bound(tls)) = tls_view {
                spans.push(Span::styled(
                    format!(" (tls {})", tls.bind),
                    Style::default().fg(Color::Cyan),
                ));
            }
        }
    }
}

fn dot(color: Color) -> Span<'static> {
    Span::styled(
        "● ",
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

fn draw_top_row(f: &mut Frame, area: Rect, state: &AppState) {
    let cols = left_right_columns(area);

    // Chain info
    let last_block_str = state.last_block_secs_ago
        .map(|s| format!("{} ago", format_duration(s)))
        .unwrap_or_else(|| "-".into());

    let hash_rate_str = if state.loaded.mining {
        state.network_hash_ps
            .map(format_hashrate)
            .unwrap_or_else(|| "-".into())
    } else {
        "loading...".into()
    };

    let chain_lines = vec![
        info_line("Network:", &state.chain_name),
        info_line("Height:", &format_num(state.blocks as u64)),
        info_line("Difficulty:", &format!("{:.3}", state.difficulty)),
        info_line("Hash Rate:", &hash_rate_str),
        info_line("Last Block:", &last_block_str),
    ];

    render_panel(f, cols[0], " Chain ", &chain_lines);

    // Latest block
    let block_title = format!("Latest Block (#{}) ", format_num(state.blocks as u64));
    if !state.loaded.block_stats {
        render_loading_panel(f, cols[1], &block_title);
    } else {
        let txs_str = state.block_stats_txs.map(format_num).unwrap_or("-".into());
        let size_str = state.block_stats_size.map(format_bytes).unwrap_or("-".into());
        let weight_str = state.block_stats_weight
            .map(|w| format!("{} WU", format_num(w)))
            .unwrap_or("-".into());
        let fees_str = state.block_stats_total_fee.map(format_btc).unwrap_or("-".into());
        let avg_rate_str = state.block_stats_avg_fee_rate
            .map(|r| format!("{:.1} sat/vB", r))
            .unwrap_or("-".into());

        let block_lines = vec![
            info_line("Hash:", &format_hash(&state.best_block_hash)),
            info_line("Txs:", &txs_str),
            info_line("Size:", &format!("{}  Weight: {}", size_str, weight_str)),
            info_line("Fees:", &fees_str),
            info_line("Avg Rate:", &avg_rate_str),
        ];

        render_panel(f, cols[1], &block_title, &block_lines);
    }
}

fn draw_middle_row(f: &mut Frame, area: Rect, state: &AppState) {
    let cols = left_right_columns(area);

    // Mempool
    let min_fee_str = if state.mempool_min_fee > 0.0 {
        // mempoolminfee is in BTC/kvB, convert to sat/vB
        format!("{:.1} sat/vB", state.mempool_min_fee * 100_000.0)
    } else {
        "1.0 sat/vB".into()
    };
    let tx_rate_str = if state.loaded.tx_stats {
        state.tx_rate.map(|r| format!("{:.1} tx/sec", r)).unwrap_or("-".into())
    } else {
        "loading...".into()
    };

    let mut mempool_lines = vec![
        info_line("Txs:", &format_num(state.mempool_size)),
        info_line("Size:", &format_bytes(state.mempool_bytes)),
        info_line("Min Rate:", &min_fee_str),
        info_line("Tx Rate:", &tx_rate_str),
    ];

    // Add size distribution sparkline
    if let Some(_dist) = &state.mempool_size_dist {
        mempool_lines.push(Line::from(Span::styled("Size Distribution:", Style::default().fg(Color::Gray))));
        // We'll render the sparkline separately
    }

    let mempool_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Mempool ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    let mempool_inner = mempool_block.inner(cols[0]);
    f.render_widget(mempool_block, cols[0]);

    for (i, line) in mempool_lines.iter().enumerate() {
        if i < mempool_inner.height as usize {
            let line_area = Rect {
                x: mempool_inner.x,
                y: mempool_inner.y + i as u16,
                width: mempool_inner.width,
                height: 1,
            };
            f.render_widget(Paragraph::new(line.clone()), line_area);
        }
    }

    // Mempool size distribution chart, under its heading on row 4.
    if let Some(dist) = &state.mempool_size_dist
        && mempool_inner.height > 5
    {
        // Labels come from the buckets the node sent, not a fixed string:
        // an old hardcoded axis had drifted and named six edges for an
        // eight-bucket histogram.
        let buckets: Vec<HistBucket> = dist
            .iter()
            .map(|b| {
                let mut label = format_vsize_edge(b.min_vsize);
                // The open-ended top bucket gets a `+`, so a row of lower
                // edges cannot be misread as closed ranges.
                if b.max_vsize.is_none() {
                    label.push('+');
                }
                HistBucket {
                    label,
                    count: b.count as u64,
                    color: Color::Cyan,
                }
            })
            .collect();
        let chart_area = Rect {
            y: mempool_inner.y + 5,
            height: mempool_inner.height - 5,
            ..mempool_inner
        };
        render_histogram(f, chart_area, &buckets, Color::Cyan);
    }

    // Fees — 4-tier mempool.space-style summary
    if !state.loaded.fee_estimates {
        render_loading_panel(f, cols[1], " Fees (sat/vB) ");
    } else {
        let fee_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " Fees (sat/vB) ",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ));
        let fee_inner = fee_block.inner(cols[1]);
        f.render_widget(fee_block, cols[1]);

        let tiers: [(&str, Option<f64>, Color); 4] = [
            ("High    (next block)", state.fees.high, Color::Red),
            ("Medium  (~30 min)   ", state.fees.medium, Color::LightRed),
            ("Low     (~1 hour)   ", state.fees.low, Color::Yellow),
            ("None    (economy)   ", state.fees.none, Color::Green),
        ];
        let max_fee = tiers
            .iter()
            .filter_map(|(_, f, _)| *f)
            .fold(0.0f64, f64::max)
            .max(1.0);

        for (i, (label, fee_opt, color)) in tiers.iter().enumerate() {
            if i >= fee_inner.height as usize {
                break;
            }
            let fee = fee_opt.unwrap_or(0.0);
            let bar_budget = (fee_inner.width as isize - 32).max(0) as f64;
            let bar_width = if max_fee > 0.0 {
                ((fee / max_fee) * bar_budget).round() as usize
            } else {
                0
            };
            let bar: String = "\u{2588}".repeat(bar_width);
            let fee_label = match fee_opt {
                Some(_) => format!("  {:.1}", fee),
                None => "  -".into(),
            };

            let line = Line::from(vec![
                Span::styled(format!("  {:<21}", label), Style::default().fg(Color::Gray)),
                Span::styled(bar, Style::default().fg(*color)),
                Span::styled(fee_label, Style::default().fg(Color::White)),
            ]);

            let line_area = Rect {
                x: fee_inner.x,
                y: fee_inner.y + i as u16,
                width: fee_inner.width,
                height: 1,
            };
            f.render_widget(Paragraph::new(line), line_area);
        }

        // Mode + confidence footer inside the fee panel.
        if fee_inner.height >= 6 {
            let mode = state.fees.mode.as_deref().unwrap_or("?");
            let conf = state.fees.confidence.as_deref().unwrap_or("?");
            let conf_color = match conf {
                "high" => Color::Green,
                "medium" => Color::Yellow,
                "low" => Color::LightRed,
                _ => Color::DarkGray,
            };
            let footer_line = Line::from(vec![
                Span::styled("  mode: ", Style::default().fg(Color::DarkGray)),
                Span::styled(mode.to_string(), Style::default().fg(Color::Cyan)),
                Span::styled("  confidence: ", Style::default().fg(Color::DarkGray)),
                Span::styled(conf.to_string(), Style::default().fg(conf_color)),
            ]);
            let footer_area = Rect {
                x: fee_inner.x,
                y: fee_inner.y + 5,
                width: fee_inner.width,
                height: 1,
            };
            f.render_widget(Paragraph::new(footer_line), footer_area);
        }
    }
}

fn draw_bottom_row(f: &mut Frame, area: Rect, state: &AppState) {
    let cols = left_right_columns(area);

    // UTXO Set
    if !state.loaded.utxo {
        render_loading_panel(f, cols[0], " UTXO Set ");
    } else {
        let utxo_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " UTXO Set ",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ));
        let utxo_inner = utxo_block.inner(cols[0]);
        f.render_widget(utxo_block, cols[0]);

        let utxo_count_str = state.utxo_count.map(format_num).unwrap_or("-".into());
        let total_str = state.utxo_total_amount
            .map(|a| format!("{:.0} BTC", a))
            .unwrap_or("-".into());
        let supply_pct = state.utxo_total_amount
            .map(|a| format!("{:.2}%", a / 21_000_000.0 * 100.0))
            .unwrap_or("-".into());

        let lines = [
            info_line("UTXOs:", &utxo_count_str),
            info_line("Total:", &total_str),
            info_line("Supply:", &supply_pct),
        ];
        for (i, line) in lines.iter().enumerate() {
            if i < utxo_inner.height as usize {
                let line_area = Rect {
                    x: utxo_inner.x,
                    y: utxo_inner.y + i as u16,
                    width: utxo_inner.width,
                    height: 1,
                };
                f.render_widget(Paragraph::new(line.clone()), line_area);
            }
        }

        // Age distribution chart: heading on row 3, chart below.
        if let Some(ref dist) = state.utxo_age_dist
            && utxo_inner.height > 4
        {
            // The node reports whether the four youngest buckets are exact.
            // Until they are (a one-time scan after upgrading), mark them.
            let estimated = state.utxo_age_exact == Some(false);
            let mut heading = vec![Span::styled(
                "Age Distribution:",
                Style::default().fg(Color::Gray),
            )];
            if estimated {
                heading.push(Span::styled(" (est.)", Style::default().fg(Color::Yellow)));
            }
            let heading_area = Rect {
                x: utxo_inner.x,
                y: utxo_inner.y + 3,
                width: utxo_inner.width,
                height: 1,
            };
            f.render_widget(Paragraph::new(Line::from(heading)), heading_area);

            let buckets: Vec<HistBucket> = UTXO_AGE_LABELS
                .iter()
                .zip(dist.iter())
                .enumerate()
                .map(|(i, (label, &count))| HistBucket {
                    label: (*label).to_string(),
                    count,
                    color: if estimated && i < 4 {
                        Color::Yellow
                    } else {
                        Color::Green
                    },
                })
                .collect();
            let chart_area = Rect {
                y: utxo_inner.y + 4,
                height: utxo_inner.height - 4,
                ..utxo_inner
            };
            render_histogram(f, chart_area, &buckets, Color::Green);
        }
    }

    // Network
    let inbound: usize = state.peers.iter()
        .filter(|p| p.get("inbound").and_then(|b| b.as_bool()).unwrap_or(false))
        .count();
    let outbound = state.connections.saturating_sub(inbound);
    let total_recv: u64 = state.peers.iter()
        .filter_map(|p| p.get("bytesrecv").and_then(|b| b.as_u64()))
        .sum();
    let total_sent: u64 = state.peers.iter()
        .filter_map(|p| p.get("bytessent").and_then(|b| b.as_u64()))
        .sum();

    let rss_str = state.rss_bytes
        .map(format_bytes)
        .unwrap_or_else(|| "-".into());
    let threads_str = state.thread_count
        .map(|t| t.to_string())
        .unwrap_or_else(|| "-".into());

    let net_lines = vec![
        info_line("Peers:", &format!("{} ({} in / {} out)", state.connections, inbound, outbound)),
        info_line("Recv:", &format_bytes(total_recv)),
        info_line("Sent:", &format_bytes(total_sent)),
        info_line("RSS:", &rss_str),
        info_line("Threads:", &threads_str),
    ];
    render_panel(f, cols[1], " Network ", &net_lines);
}

/// Split a row 40/60, but never give the left column less than
/// [`LEFT_COLUMN_MIN_WIDTH`]. The left panels hold the histogram charts, and
/// at the common 80-column terminal a plain 40% is one column short of
/// separating the bars, which runs their counts and labels together. The
/// three rows share the split so the panel borders line up.
fn left_right_columns(area: Rect) -> std::rc::Rc<[Rect]> {
    let left = (area.width * 2 / 5).max(LEFT_COLUMN_MIN_WIDTH).min(area.width);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(left), Constraint::Min(0)])
        .split(area)
}

/// Eight three-column bars with one-column gaps (31), one more column for the
/// `+` of the mempool's open-ended `50k+` label (1), and the border (2).
const LEFT_COLUMN_MIN_WIDTH: u16 = 8 * HIST_BAR_WIDTH + 7 + 1 + 2;

/// `gettxoutsetinfo`'s eight age buckets, in three characters each.
const UTXO_AGE_LABELS: [&str; 8] = ["<1h", "<1d", "<1w", "<1m", "<6m", "<1y", "<3y", "3y+"];

/// Columns per histogram bar: every age label and every count
/// `format_count3` prints fits in three.
const HIST_BAR_WIDTH: u16 = 3;

/// One bucket of a histogram chart.
struct HistBucket {
    label: String,
    count: u64,
    color: Color,
}

/// Draw a histogram into `area`: a vertical bar chart on a log scale (see
/// [`log_bar`]), each bucket's count printed on its bar, labels on the bottom
/// row. Eight three-column bars take 31 columns with a one-column gap and 24
/// without; the gap goes when the area is narrower than 31.
///
/// When the area leaves fewer than two rows for bars, or is too narrow for
/// three-column bars, it falls back to a one-row sparkline on the same log
/// scale with the labels beneath, so nothing is drawn over the labels.
fn render_histogram(f: &mut Frame, area: Rect, buckets: &[HistBucket], color: Color) {
    if area.height == 0 || area.width == 0 || buckets.is_empty() {
        return;
    }
    let n = buckets.len() as u16;
    let bars_width = n * HIST_BAR_WIDTH;
    let bar_rows = area.height - 1;
    let label_style = Style::default().fg(Color::DarkGray);

    if bar_rows < 2 || area.width < bars_width {
        let data: Vec<u64> = buckets.iter().map(|b| log_bar(b.count)).collect();
        let spark_area = Rect {
            width: area.width.min(n),
            height: 1,
            ..area
        };
        f.render_widget(
            Sparkline::default()
                .data(&data)
                .style(Style::default().fg(color)),
            spark_area,
        );
        if area.height > 1 {
            let axis = buckets
                .iter()
                .map(|b| b.label.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let axis_area = Rect {
                y: area.y + 1,
                height: 1,
                ..area
            };
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(axis, label_style))),
                axis_area,
            );
        }
        return;
    }

    let gap = u16::from(area.width >= bars_width + (n - 1));
    let bars: Vec<Bar> = buckets
        .iter()
        .map(|b| {
            Bar::default()
                .value(log_bar(b.count))
                .text_value(format_count3(b.count))
                .style(Style::default().fg(b.color))
        })
        .collect();
    let chart = BarChart::new(bars)
        .bar_width(HIST_BAR_WIDTH)
        .bar_gap(gap)
        .value_style(Style::default().fg(Color::White));
    f.render_widget(
        chart,
        Rect {
            height: bar_rows,
            ..area
        },
    );
    let axis = histogram_axis(buckets.iter().map(|b| b.label.as_str()), HIST_BAR_WIDTH, gap);
    let axis_area = Rect {
        y: area.y + bar_rows,
        height: 1,
        ..area
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(axis, label_style))),
        axis_area,
    );
}

/// The label row under a bar chart. Each label is centred under its bar the
/// way ratatui centres a bar's own label, but drawn here rather than by the
/// chart because the chart clips a label to its bar's width, and the
/// mempool's open-ended top bucket (`50k+`) is one column wider. The last
/// label may run past its bar; the others are clipped to it.
fn histogram_axis<'a>(labels: impl Iterator<Item = &'a str>, bar_width: u16, gap: u16) -> String {
    let labels: Vec<&str> = labels.collect();
    let mut out = String::new();
    for (i, label) in labels.iter().enumerate() {
        let label: String = if i + 1 == labels.len() {
            (*label).to_string()
        } else {
            label.chars().take(bar_width as usize).collect()
        };
        let pad = (bar_width as usize).saturating_sub(label.chars().count()) / 2;
        let column = i * (bar_width + gap) as usize + pad;
        let used = out.chars().count();
        out.push_str(&" ".repeat(column.saturating_sub(used)));
        out.push_str(&label);
    }
    out
}

fn info_line<'a>(label: &'a str, value: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{:<13}", label), Style::default().fg(Color::Gray)),
        Span::styled(value.to_string(), Style::default().fg(Color::White)),
    ])
}

fn render_panel(f: &mut Frame, area: Rect, title: &str, lines: &[Line<'_>]) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title.to_string(),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    for (i, line) in lines.iter().enumerate() {
        if i < inner.height as usize {
            let line_area = Rect {
                x: inner.x,
                y: inner.y + i as u16,
                width: inner.width,
                height: 1,
            };
            f.render_widget(Paragraph::new(line.clone()), line_area);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AppState, SpIndexProgress};

    /// Mainnet-shaped inputs: the mempool vsize histogram and UTXO age
    /// counts from a synced mainnet node. Both span several decades, which
    /// is what the log scale is for.
    fn histogram_state(exact: Option<bool>) -> AppState {
        let mut st = AppState::new();
        let mut age = serde_json::json!({
            "counts": [391947, 0, 997122, 2014141, 9811843, 10483379, 70283989, 71216488],
        });
        if let Some(exact) = exact {
            age["exact"] = serde_json::json!(exact);
        }
        st.update_utxo_info(&serde_json::json!({
            "txouts": 165_198_909u64,
            "total_amount": 19_930_000.0,
            "utxo_age_distribution": age,
        }));
        let edges = [0u64, 100, 250, 500, 1_000, 5_000, 10_000, 50_000];
        let counts = [273u64, 10_399, 932, 330, 204, 55, 18, 3];
        let histogram: Vec<serde_json::Value> = edges
            .iter()
            .zip(counts)
            .enumerate()
            .map(|(i, (min, count))| {
                serde_json::json!({
                    "min_vsize": min,
                    "max_vsize": edges.get(i + 1),
                    "count": count,
                })
            })
            .collect();
        st.update_mempool_dist(&serde_json::json!({"vsize_histogram": histogram, "top": []}));
        st
    }

    /// Render the steady view into a test terminal and return its rows.
    fn render_steady(width: u16, height: u16, state: &AppState) -> Vec<String> {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, state)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect()
    }

    #[test]
    fn steady_view_draws_both_histograms_as_labelled_log_bar_charts() {
        for (width, height) in [(80, 40), (120, 40)] {
            for exact in [Some(true), Some(false), None] {
                let rows = render_steady(width, height, &histogram_state(exact));
                let screen = rows.join("\n");
                let ctx = format!("{width}x{height} exact={exact:?}\n{screen}");
                // Every bucket's label, the open bucket's `+` included.
                assert!(screen.contains("<1h"), "{ctx}");
                assert!(screen.contains("3y+"), "{ctx}");
                assert!(screen.contains("50k+"), "{ctx}");
                // Counts on the bars, at both ends of each distribution: the
                // largest buckets and the three-transaction tail.
                assert!(screen.contains("71M"), "{ctx}");
                assert!(screen.contains(".3M"), "{ctx}");
                assert!(screen.contains("10k"), "{ctx}");
                // The mempool's value row carries every bucket's count, down
                // to the 18- and 3-transaction tail a linear scale lost.
                let values = rows
                    .iter()
                    .find(|r| r.contains("273 10k 932"))
                    .unwrap_or_else(|| panic!("no mempool value row: {ctx}"));
                let tail = &values[values.find("18").expect("the 18-tx bucket")..];
                assert!(tail[2..].contains('3'), "the 3-tx bucket: {ctx}");
                // Separated bars: the labels read as the old fixed axis did.
                assert!(screen.contains("<1h <1d <1w <1m"), "{ctx}");
                assert!(screen.contains("10k 50k+"), "{ctx}");
                assert_eq!(screen.contains("(est.)"), exact == Some(false), "{ctx}");
                // Bars are drawn in more than one row: a chart, not a
                // one-row sparkline.
                let bar_rows = rows.iter().filter(|r| r.contains('█')).count();
                assert!(bar_rows >= 4, "{ctx}");
            }
        }
    }

    #[test]
    fn steady_view_on_a_short_terminal_renders_without_panicking() {
        // Too short for the fixed panel heights: the layout squeezes the
        // panels and the charts must degrade instead of panicking.
        for (width, height) in [(80, 24), (60, 20), (40, 12), (20, 8)] {
            let rows = render_steady(width, height, &histogram_state(Some(false)));
            assert_eq!(rows.len(), height as usize);
        }
    }

    /// Render only a histogram, into an area of the given size.
    fn render_histogram_rows(width: u16, height: u16) -> Vec<String> {
        let counts = [273u64, 10_399, 932, 330, 204, 55, 18, 3];
        let buckets: Vec<HistBucket> = UTXO_AGE_LABELS
            .iter()
            .zip(counts)
            .map(|(label, count)| HistBucket {
                label: (*label).to_string(),
                count,
                color: Color::Cyan,
            })
            .collect();
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|f| render_histogram(f, f.area(), &buckets, Color::Cyan))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect()
    }

    #[test]
    fn histogram_with_room_for_one_bar_row_is_a_sparkline() {
        // Two rows: one would be left for bars, and the counts printed on
        // that row would hide them. The fallback draws a sparkline there
        // instead, with the labels still beneath.
        let rows = render_histogram_rows(40, 2);
        assert!(!rows[0].chars().any(|c| c.is_ascii_digit()), "{rows:#?}");
        let glyphs = |r: &str| r.chars().filter(|c| "▁▂▃▄▅▆▇█".contains(*c)).count();
        assert!(glyphs(&rows[0]) >= 7, "one glyph per non-empty bucket: {rows:#?}");
        assert!(rows[1].starts_with("<1h <1d"), "{rows:#?}");
        // Too narrow for eight three-column bars: the same fallback.
        let rows = render_histogram_rows(20, 6);
        assert!(!rows[0].chars().any(|c| c.is_ascii_digit()), "{rows:#?}");
        assert!(rows[2..].iter().all(|r| r.trim().is_empty()), "{rows:#?}");
        // Three rows is a real chart: two bar rows, counts, labels.
        let rows = render_histogram_rows(40, 3);
        assert!(rows[1].contains("10k"), "{rows:#?}");
        assert!(rows[2].starts_with("<1h <1d"), "{rows:#?}");
    }

    #[test]
    fn left_column_is_wide_enough_for_separated_bars() {
        let at = |width| left_right_columns(Rect::new(0, 0, width, 10))[0].width;
        assert_eq!(at(80), LEFT_COLUMN_MIN_WIDTH, "a plain 40% would be 32");
        assert_eq!(LEFT_COLUMN_MIN_WIDTH, 34);
        assert_eq!(at(120), 48, "unchanged where 40% is already enough");
        assert_eq!(at(20), 20, "never wider than the row");
    }

    #[test]
    fn histogram_axis_centres_labels_and_lets_the_last_run_on() {
        let ages = ["<1h", "<1d", "<1w", "<1m", "<6m", "<1y", "<3y", "3y+"];
        // The axis the sparkline used to carry as a fixed string.
        assert_eq!(
            histogram_axis(ages.iter().copied(), 3, 1),
            "<1h <1d <1w <1m <6m <1y <3y 3y+"
        );
        assert_eq!(
            histogram_axis(ages.iter().copied(), 3, 0),
            "<1h<1d<1w<1m<6m<1y<3y3y+"
        );
        let vsize = ["0", "100", "250", "500", "1k", "5k", "10k", "50k+"];
        assert_eq!(
            histogram_axis(vsize.iter().copied(), 3, 1),
            " 0  100 250 500 1k  5k  10k 50k+"
        );
    }

    /// Render the services row to a plain string, dropping styling.
    fn row(state: &AppState) -> String {
        services_line(state)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<String>()
    }

    fn sp(enabled: bool, synced: bool, state: &str) -> SpIndexProgress {
        SpIndexProgress {
            enabled: Some(enabled),
            synced,
            state: state.to_string(),
            cursor_height: 835_200,
            snapshot_height: 962_151,
            // Daemon-computed from walk_start=709,632 on this mainnet
            // shape; cursor/snapshot would misread it as 86.8%.
            progress_ratio: Some(0.497_263_583),
            estimated_remaining_seconds: 0,
            last_error: None,
        }
    }

    #[test]
    fn services_row_has_no_sp_column_when_daemon_never_reported_one() {
        let st = AppState::new();
        assert!(st.sp_index.is_none());
        assert!(!row(&st).contains("sp-idx"));
    }

    #[test]
    fn services_row_has_no_sp_column_when_index_is_off() {
        let mut st = AppState::new();
        st.sp_index = Some(sp(false, false, "idle"));
        let r = row(&st);
        assert!(!r.contains("sp-idx"), "disabled index must not take a column: {r}");
        // The other three columns are untouched.
        assert!(r.contains("addr-idx"));
        assert!(r.contains("esplora"));
        assert!(r.contains("electrum"));
    }

    #[test]
    fn services_row_shows_synced_sp_column() {
        let mut st = AppState::new();
        st.sp_index = Some(sp(true, true, "completed"));
        let r = row(&st);
        assert!(r.contains("sp-idx synced"), "{r}");
    }

    #[test]
    fn services_row_shows_syncing_when_enabled_but_not_caught_up() {
        let mut st = AppState::new();
        st.sp_index = Some(sp(true, false, "idle"));
        let r = row(&st);
        assert!(r.contains("sp-idx syncing"), "{r}");
    }

    #[test]
    fn services_row_shows_daemon_reported_backfill_progress() {
        let mut st = AppState::new();
        st.sp_index = Some(sp(true, false, "running"));
        let r = row(&st);
        // The daemon's walk-start-based ratio, verbatim: 49.7%. Two
        // plausible-looking wrong reconstructions from the same counts
        // must NOT appear: cursor/snapshot measures from genesis and
        // gives 86.8%; the address index's two-pass maths gives 43.4%.
        assert!(r.contains("sp-idx backfill 49.7%"), "{r}");
        assert!(
            !r.contains("86.8%"),
            "cursor/snapshot (genesis-measured) reconstruction: {r}"
        );
        assert!(!r.contains("43.4%"), "two-pass reconstruction: {r}");
        assert!(r.contains("(835,200/962,151)"), "{r}");
        assert!(!r.contains("pass"), "single-pass backfill must not show a pass counter: {r}");
    }

    #[test]
    fn services_row_omits_percentage_when_daemon_sends_no_ratio() {
        // Old daemon: counts and ETA only. Rendering a percentage here
        // would require reconstructing it from cursor/snapshot, which is
        // genesis-measured and wrong (86.8% for a ~49.7%-done walk).
        let mut st = AppState::new();
        let mut p = sp(true, false, "running");
        p.enabled = None;
        p.progress_ratio = None;
        p.estimated_remaining_seconds = 7_200;
        st.sp_index = Some(p);
        let r = row(&st);
        assert!(r.contains("sp-idx backfill (835,200/962,151)"), "{r}");
        assert!(!r.contains('%'), "no ratio from the daemon, no percentage: {r}");
        assert!(r.contains("ETA"), "{r}");
    }

    #[test]
    fn services_row_hides_sp_column_when_disabled_with_stale_cursor() {
        // Explicit enabled=false beats a leftover running cursor: the
        // supervisor will not resume it while the index is off, so a
        // green backfill column would report work that is not happening.
        let mut st = AppState::new();
        st.sp_index = Some(sp(false, false, "running"));
        let r = row(&st);
        assert!(!r.contains("sp-idx"), "disabled index must not take a column: {r}");
    }

    #[test]
    fn sp_column_sits_between_addr_index_and_esplora() {
        let mut st = AppState::new();
        st.sp_index = Some(sp(true, true, "completed"));
        let r = row(&st);
        let addr = r.find("addr-idx").expect("addr-idx present");
        let spi = r.find("sp-idx").expect("sp-idx present");
        let esp = r.find("esplora").expect("esplora present");
        assert!(addr < spi && spi < esp, "column order wrong: {r}");
    }

    #[test]
    fn failed_sp_backfill_surfaces_the_error() {
        let mut st = AppState::new();
        let mut p = sp(true, false, "failed");
        p.last_error = Some("disk full".into());
        st.sp_index = Some(p);
        let r = row(&st);
        assert!(r.contains("backfill FAILED — disk full"), "{r}");
    }
}
