use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline};

use crate::state::AppState;
use crate::ui::{
    format_bytes, format_btc, format_duration, format_hash, format_hashrate, format_num,
    peer_table, render_loading_panel,
};

pub fn draw(f: &mut Frame, state: &AppState) {
    let size = f.area();

    let constraints = vec![
        Constraint::Length(1),  // title
        Constraint::Length(9),  // chain + latest block
        Constraint::Length(11), // mempool + fee estimates
        Constraint::Length(9),  // utxo + network
        Constraint::Min(5),     // peers
        Constraint::Length(1),  // services status (addr-index, esplora, electrum)
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
        Span::styled(" v0.1.0 ", Style::default().fg(Color::DarkGray)),
        Span::styled(uptime_str, Style::default().fg(Color::DarkGray)),
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

    // Services row — always visible. Shows addr-index, Esplora, and
    // Electrum status side-by-side. When a backfill is running /
    // paused / failed, the addr-index column shows backfill progress
    // instead of the steady-state synced/syncing label.
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

/// Single-line services row. Three columns separated by two spaces:
/// `addr-idx <state>`, `esplora <state>`, `electrum <state>`.
///
/// `<state>` for addr-idx is the backfill summary when one is active
/// (running / paused / failed), the live `synced` / `lagging` / `off`
/// label otherwise. For listeners it is the bind address when
/// enabled, `off` (dim) otherwise. Listener TLS binds, when present,
/// follow the plain bind in parentheses.
fn services_line(state: &AppState) -> Line<'static> {
    let mut spans = Vec::new();
    spans.push(Span::raw(" "));
    addr_index_spans(&mut spans, state);
    spans.push(Span::raw("  "));
    listener_spans(
        &mut spans,
        "esplora",
        state.server_status.esplora.as_ref().map(|l| l.bind.as_str()),
        None,
    );
    spans.push(Span::raw("  "));
    listener_spans(
        &mut spans,
        "electrum",
        state.server_status.electrum.as_ref().map(|l| l.bind.as_str()),
        state
            .server_status
            .electrum_tls
            .as_ref()
            .map(|l| l.bind.as_str()),
    );
    Line::from(spans)
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
    match state.server_status.addressindex.as_ref() {
        None => {
            // No status from satd yet (first poll, older satd, transient
            // RPC error). Stay neutral — don't claim disabled.
            spans.push(dot(Color::DarkGray));
            spans.push(Span::styled(label, Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(" -", Style::default().fg(Color::DarkGray)));
        }
        Some(ai) if !ai.enabled => {
            spans.push(dot(Color::DarkGray));
            spans.push(Span::styled(label, Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(" off", Style::default().fg(Color::DarkGray)));
        }
        Some(ai) if ai.complete => {
            spans.push(dot(Color::Green));
            spans.push(Span::styled(label, Style::default().fg(Color::White)));
            spans.push(Span::styled(" synced", Style::default().fg(Color::Gray)));
        }
        Some(_) => {
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
    bind: Option<&str>,
    tls_bind: Option<&str>,
) {
    match bind {
        Some(b) => {
            spans.push(dot(Color::Green));
            spans.push(Span::styled(label, Style::default().fg(Color::White)));
            spans.push(Span::styled(
                format!(" {}", b),
                Style::default().fg(Color::Gray),
            ));
            if let Some(tls) = tls_bind {
                spans.push(Span::styled(
                    format!(" (tls {})", tls),
                    Style::default().fg(Color::Cyan),
                ));
            }
        }
        None => {
            spans.push(dot(Color::DarkGray));
            spans.push(Span::styled(label, Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(" off", Style::default().fg(Color::DarkGray)));
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
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

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
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

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

    // Mempool size distribution sparkline
    if let Some(dist) = &state.mempool_size_dist {
        let dist_data: Vec<u64> = dist.iter().map(|&v| v as u64).collect();
        if mempool_inner.height > 5 {
            let spark_area = Rect {
                x: mempool_inner.x,
                y: mempool_inner.y + 5,
                width: mempool_inner.width.min(16),
                height: 1,
            };
            let spark = Sparkline::default()
                .data(&dist_data)
                .style(Style::default().fg(Color::Cyan));
            f.render_widget(spark, spark_area);

            if mempool_inner.height > 6 {
                let label_area = Rect {
                    x: mempool_inner.x,
                    y: mempool_inner.y + 6,
                    width: mempool_inner.width,
                    height: 1,
                };
                f.render_widget(
                    Paragraph::new(Line::from(Span::styled(
                        "0   250  500  1k  5k  50k",
                        Style::default().fg(Color::DarkGray),
                    ))),
                    label_area,
                );
            }
        }
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
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

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

        // Age distribution sparkline
        if let Some(ref dist) = state.utxo_age_dist
            && utxo_inner.height > 4 {
                let label_area = Rect {
                    x: utxo_inner.x,
                    y: utxo_inner.y + 3,
                    width: utxo_inner.width,
                    height: 1,
                };
                f.render_widget(
                    Paragraph::new(Line::from(Span::styled("Age Distribution:", Style::default().fg(Color::Gray)))),
                    label_area,
                );

                let dist_data: Vec<u64> = dist.to_vec();
                let spark_area = Rect {
                    x: utxo_inner.x,
                    y: utxo_inner.y + 4,
                    width: utxo_inner.width.min(16),
                    height: 1,
                };
                let spark = Sparkline::default()
                    .data(&dist_data)
                    .style(Style::default().fg(Color::Green));
                f.render_widget(spark, spark_area);

                if utxo_inner.height > 5 {
                    let scale_area = Rect {
                        x: utxo_inner.x,
                        y: utxo_inner.y + 5,
                        width: utxo_inner.width,
                        height: 1,
                    };
                    f.render_widget(
                        Paragraph::new(Line::from(Span::styled(
                            "<1h <1d <1w <1m <6m <1y <3y 3y+",
                            Style::default().fg(Color::DarkGray),
                        ))),
                        scale_area,
                    );
                }
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
