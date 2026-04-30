use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table};

use crate::state::{AppState, FeeSummary, MempoolSnapshot, MempoolTopEntry};
use crate::ui::{format_bytes, format_duration, format_hash, format_num};

/// Feerate display buckets (sat/vB): (min_inclusive, max_exclusive, label).
/// The final bucket has u64::MAX as upper bound.
const FEERATE_BUCKETS: &[(u64, u64, &str)] = &[
    (1, 2, "1-2"),
    (2, 5, "2-5"),
    (5, 10, "5-10"),
    (10, 20, "10-20"),
    (20, 50, "20-50"),
    (50, 100, "50-100"),
    (100, 500, "100-500"),
    (500, u64::MAX, "500+"),
];

pub fn draw(f: &mut Frame, state: &AppState) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // title
            Constraint::Length(4),  // summary strip
            Constraint::Min(14),    // histogram + tiers
            Constraint::Length(12), // trend + top-N row
            Constraint::Length(1),  // footer
        ])
        .split(size);

    draw_title(f, chunks[0], state);
    draw_summary(f, chunks[1], state);
    draw_histogram(f, chunks[2], state);
    draw_trend_and_top(f, chunks[3], state);
    draw_footer(f, chunks[4]);
}

fn draw_title(f: &mut Frame, area: Rect, state: &AppState) {
    let (dot_glyph, dot_color, health_label) = if state.is_healthy() {
        ("● ", Color::Green, "ready")
    } else if state.stale || !state.connected {
        ("✕ ", Color::Red, "stale")
    } else {
        ("○ ", Color::Yellow, "syncing")
    };
    let uptime_str = state.uptime_secs
        .map(|s| format!(" up {} ", format_duration(s)))
        .unwrap_or_default();
    let title = Line::from(vec![
        Span::styled(" satd ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!(" {} ", state.chain_name),
            Style::default().fg(Color::White),
        ),
        Span::styled(dot_glyph, Style::default().fg(dot_color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{} ", health_label), Style::default().fg(dot_color)),
        Span::styled(" mempool ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(uptime_str, Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(title), area);
}

fn draw_summary(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Summary ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let min_rate = if state.mempool_min_fee > 0.0 {
        format!("{:.1} sat/vB", state.mempool_min_fee * 100_000.0)
    } else {
        "1.0 sat/vB".into()
    };

    // Latest snapshot gives us max fee and netdelta.
    let (max_rate, delta_str) = if let Some(last) = state.mempool_history.last() {
        let mx = last.max_fee_rate_sat_per_kvb as f64 / 1_000.0;
        let mx_str = if mx > 0.0 { format!("{:.1}", mx) } else { "-".into() };
        let delta = if state.mempool_size == 0 {
            // Distinguish "we have data, mempool is genuinely empty" from
            // "we're still waiting for our second history snapshot". Both
            // produce the same on-screen result without this branch.
            "mempool empty — node receiving no relayed txs (still catching up?)".into()
        } else if let Some((dtx, dbytes, secs)) = state.latest_mempool_delta() {
            let tx_sign = if dtx >= 0 { "+" } else { "" };
            let bytes_str = if dbytes >= 0 {
                format!("+{}", format_bytes(dbytes as u64))
            } else {
                format!("-{}", format_bytes((-dbytes) as u64))
            };
            format!("Δ last {}s: {}{} tx · {}", secs, tx_sign, dtx, bytes_str)
        } else {
            "Δ --- awaiting second snapshot".into()
        };
        (mx_str, delta)
    } else if !state.mempool_history_available {
        ("-".into(), "history: disabled (no writable datadir)".into())
    } else {
        ("-".into(), "awaiting history snapshots...".into())
    };

    let line1 = Line::from(vec![
        Span::styled("  Txs ", Style::default().fg(Color::Gray)),
        Span::styled(format_num(state.mempool_size), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("   Bytes ", Style::default().fg(Color::Gray)),
        Span::styled(format_bytes(state.mempool_bytes), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("   Min ", Style::default().fg(Color::Gray)),
        Span::styled(min_rate, Style::default().fg(Color::White)),
        Span::styled("   Max ", Style::default().fg(Color::Gray)),
        Span::styled(format!("{} sat/vB", max_rate), Style::default().fg(Color::White)),
    ]);
    let line2 = Line::from(vec![
        Span::styled(format!("  {}", delta_str), Style::default().fg(Color::DarkGray)),
    ]);

    render_lines(f, inner, &[line1, line2]);
}

fn draw_histogram(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Feerate histogram (vbytes per sat/vB band) ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let aggregated = aggregate_histogram(state.mempool_history.last());
    let total_weight: u64 = aggregated.iter().map(|(_, w)| *w).sum();

    // Empty mempool — paint a centered "no data" message and skip the bars
    // entirely (zero-width bars just look like a misrendered panel).
    if total_weight == 0 && inner.height >= 3 {
        let msg_y = inner.y + (inner.height.saturating_sub(3)) / 2;
        let msg_area = Rect { x: inner.x, y: msg_y, width: inner.width, height: 1 };
        let msg = if state.mempool_size == 0 {
            "Mempool is empty — no fee distribution to display."
        } else {
            "Awaiting first feerate snapshot..."
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                msg.to_string(),
                Style::default().fg(Color::DarkGray),
            )))
            .alignment(ratatui::layout::Alignment::Center),
            msg_area,
        );
        // Still render the tier overlay below — even with empty mempool the
        // estimator returns floor values that are useful to see.
        draw_histogram_footer(f, inner, state);
        return;
    }

    let max_weight = aggregated.iter().map(|(_, w)| *w).max().unwrap_or(1).max(1);
    let bar_budget = (inner.width as isize - 30).max(0) as u64;

    // Compute fee-tier cutoffs (in sat/vB) for overlay labels.
    let tier_values = [
        ("None", state.fees.none, Color::Green),
        ("Low", state.fees.low, Color::Yellow),
        ("Medium", state.fees.medium, Color::LightRed),
        ("High", state.fees.high, Color::Red),
    ];

    // Histogram bars (one per bucket) top-down.
    let rows_available = inner.height.saturating_sub(3) as usize; // leave 3 for tier footer
    for (i, ((lo, _hi, label), (_, weight))) in FEERATE_BUCKETS
        .iter()
        .zip(aggregated.iter())
        .enumerate()
        .take(rows_available)
    {
        let bar_width = if max_weight > 0 {
            ((*weight * bar_budget) / max_weight) as usize
        } else {
            0
        };
        let color = tier_color_for_rate(*lo, &tier_values);
        let bar = "\u{2588}".repeat(bar_width);
        // Mempool bytes = weight / 4 vbytes (segwit-aware). Report vbytes.
        let vbytes = weight / 4;
        let line = Line::from(vec![
            Span::styled(format!("  {:<9}", label), Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{:<10}", "sat/vB"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(bar, Style::default().fg(color)),
            Span::styled(format!("  {}", format_bytes(vbytes)), Style::default().fg(Color::White)),
        ]);
        let row = Rect {
            x: inner.x,
            y: inner.y + i as u16,
            width: inner.width,
            height: 1,
        };
        f.render_widget(Paragraph::new(line), row);
    }

    draw_histogram_footer(f, inner, state);
}

fn draw_histogram_footer(f: &mut Frame, inner: Rect, state: &AppState) {
    if inner.height < 3 {
        return;
    }
    let tier_line = Line::from(tier_spans(&state.fees));
    let tier_row = Rect {
        x: inner.x,
        y: inner.y + inner.height - 2,
        width: inner.width,
        height: 1,
    };
    f.render_widget(Paragraph::new(tier_line), tier_row);

    let mode = state.fees.mode.as_deref().unwrap_or("?");
    let conf = state.fees.confidence.as_deref().unwrap_or("?");
    let conf_color = match conf {
        "high" => Color::Green,
        "medium" => Color::Yellow,
        "low" => Color::LightRed,
        _ => Color::DarkGray,
    };
    let mode_line = Line::from(vec![
        Span::styled("  mode ", Style::default().fg(Color::DarkGray)),
        Span::styled(mode.to_string(), Style::default().fg(Color::Cyan)),
        Span::styled("   confidence ", Style::default().fg(Color::DarkGray)),
        Span::styled(conf.to_string(), Style::default().fg(conf_color)),
    ]);
    let mode_row = Rect {
        x: inner.x,
        y: inner.y + inner.height - 1,
        width: inner.width,
        height: 1,
    };
    f.render_widget(Paragraph::new(mode_line), mode_row);
}

fn tier_spans(fees: &FeeSummary) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = vec![Span::styled(
        "  Tiers (sat/vB)  ",
        Style::default().fg(Color::Gray),
    )];
    let rows = [
        ("High ", fees.high, Color::Red),
        ("Medium ", fees.medium, Color::LightRed),
        ("Low ", fees.low, Color::Yellow),
        ("None ", fees.none, Color::Green),
    ];
    for (i, (label, v, color)) in rows.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("   ", Style::default()));
        }
        spans.push(Span::styled((*label).to_string(), Style::default().fg(Color::DarkGray)));
        let val = v.map(|n| format!("{:.1}", n)).unwrap_or_else(|| "-".into());
        spans.push(Span::styled(val, Style::default().fg(*color).add_modifier(Modifier::BOLD)));
    }
    spans
}

fn tier_color_for_rate(rate_sat_per_vb: u64, tiers: &[(&str, Option<f64>, Color); 4]) -> Color {
    // Walk from None → High; bar color = color of the highest tier we exceed.
    let mut color = Color::Gray;
    for (_, v, c) in tiers {
        if let Some(cut) = v
            && rate_sat_per_vb as f64 >= *cut
        {
            color = *c;
        }
    }
    color
}

/// Aggregate wire histogram (feerate_sat_per_kvb, weight) into display buckets.
fn aggregate_histogram(snap: Option<&MempoolSnapshot>) -> Vec<(&'static str, u64)> {
    let mut out: Vec<(&'static str, u64)> = FEERATE_BUCKETS.iter().map(|(_, _, l)| (*l, 0u64)).collect();
    let Some(snap) = snap else { return out };
    for b in &snap.histogram {
        let rate_vb = b.feerate_sat_per_kvb / 1_000;
        for (i, (lo, hi, _)) in FEERATE_BUCKETS.iter().enumerate() {
            if rate_vb >= *lo && rate_vb < *hi {
                out[i].1 += b.weight;
                break;
            }
        }
    }
    out
}

fn draw_trend_and_top(f: &mut Frame, area: Rect, state: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    draw_trend(f, cols[0], state);
    draw_top_n(f, cols[1], state);
}

fn draw_trend(f: &mut Frame, area: Rect, state: &AppState) {
    let title = if !state.mempool_history_available {
        " Trend (disabled) "
    } else if state.mempool_history.is_empty() {
        " Trend (waiting...) "
    } else {
        " Trend (~40m) "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title,
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);
    if state.mempool_history.is_empty() || inner.height < 6 {
        return;
    }

    let bytes: Vec<u64> = state.mempool_history.iter().map(|s| s.bytes).collect();
    let txs: Vec<u64> = state.mempool_history.iter().map(|s| s.size).collect();
    let min_fees: Vec<u64> = state.mempool_history.iter().map(|s| s.min_fee_rate_sat_per_kvb).collect();

    // All-zero history (e.g. mempool stayed empty during catch-up) makes
    // sparklines render as a flat invisible line — paint a hint instead.
    if bytes.iter().all(|b| *b == 0) && txs.iter().all(|t| *t == 0) {
        let msg_y = inner.y + inner.height / 2;
        let msg_area = Rect { x: inner.x, y: msg_y, width: inner.width, height: 1 };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no mempool activity yet",
                Style::default().fg(Color::DarkGray),
            )))
            .alignment(ratatui::layout::Alignment::Center),
            msg_area,
        );
        return;
    }

    // 2-row blocks: one label row + one sparkline row each.
    let rows = [
        ("Bytes  ", &bytes, Color::Cyan),
        ("Txs    ", &txs, Color::Green),
        ("MinFee ", &min_fees, Color::Yellow),
    ];
    let slot_h = (inner.height / 3).max(2);
    for (i, (label, data, color)) in rows.iter().enumerate() {
        let y = inner.y + (i as u16) * slot_h;
        if y + slot_h > inner.y + inner.height {
            break;
        }
        let label_area = Rect { x: inner.x, y, width: inner.width, height: 1 };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("  {}", label), Style::default().fg(Color::Gray)),
                Span::styled(
                    summarise(data),
                    Style::default().fg(Color::DarkGray),
                ),
            ])),
            label_area,
        );
        let spark_area = Rect {
            x: inner.x + 2,
            y: y + 1,
            width: inner.width.saturating_sub(4),
            height: slot_h.saturating_sub(1),
        };
        let spark = Sparkline::default()
            .data(data.as_slice())
            .style(Style::default().fg(*color));
        f.render_widget(spark, spark_area);
    }
}

fn summarise(data: &[u64]) -> String {
    if data.is_empty() {
        return "-".into();
    }
    let last = *data.last().unwrap();
    let max = *data.iter().max().unwrap_or(&0);
    if max == 0 {
        "-".into()
    } else {
        format!("now {} · max {}", last, max)
    }
}

fn draw_top_n(f: &mut Frame, area: Rect, state: &AppState) {
    let title = format!(
        " Top by ancestor feerate ({} in mempool) ",
        format_num(state.mempool_size),
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title,
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));

    if state.mempool_top.is_empty() {
        let inner = block.inner(area);
        f.render_widget(block, area);
        if inner.height >= 1 {
            let msg_y = inner.y + inner.height / 2;
            let msg_area = Rect { x: inner.x, y: msg_y, width: inner.width, height: 1 };
            let msg = if state.mempool_size == 0 {
                "Mempool is empty — no transactions to rank."
            } else {
                "Awaiting verbose mempool snapshot..."
            };
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    msg.to_string(),
                    Style::default().fg(Color::DarkGray),
                )))
                .alignment(ratatui::layout::Alignment::Center),
                msg_area,
            );
        }
        return;
    }

    let header = Row::new(vec!["#", "txid", "vsize", "anc sat/vB", "A/D", "age"])
        .style(Style::default().fg(Color::Cyan));
    let widths = vec![
        Constraint::Length(3),
        Constraint::Min(18),
        Constraint::Length(7),
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(8),
    ];

    let rows: Vec<Row> = state
        .mempool_top
        .iter()
        .enumerate()
        .map(|(i, e)| top_row(i, e, i == state.selected_mempool_row))
        .collect();

    let table = Table::new(rows, widths).header(header).block(block);
    f.render_widget(table, area);
}

fn top_row(i: usize, e: &MempoolTopEntry, selected: bool) -> Row<'static> {
    let base = Style::default();
    let style = if selected { base.fg(Color::Yellow) } else { base };
    Row::new(vec![
        Cell::from(format!("{}", i + 1)),
        Cell::from(format_hash(&e.txid)),
        Cell::from(format_num(e.vsize)),
        Cell::from(format!("{:.2}", e.ancestor_feerate)),
        Cell::from(format!("{}/{}", e.ancestor_count, e.descendant_count)),
        Cell::from(format_duration(e.age_secs)),
    ])
    .style(style)
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::White)),
        Span::styled(": quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled("h", Style::default().fg(Color::White)),
        Span::styled(": help  ", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::White)),
        Span::styled(": reorgs  ", Style::default().fg(Color::DarkGray)),
        Span::styled("1/2/3/4", Style::default().fg(Color::White)),
        Span::styled(": view  ", Style::default().fg(Color::DarkGray)),
        Span::raw("\u{2191}\u{2193}"),
        Span::styled(": scroll top-N", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(footer), area);
}

fn render_lines(f: &mut Frame, inner: Rect, lines: &[Line<'_>]) {
    for (i, line) in lines.iter().enumerate() {
        if i < inner.height as usize {
            let row = Rect {
                x: inner.x,
                y: inner.y + i as u16,
                width: inner.width,
                height: 1,
            };
            f.render_widget(Paragraph::new(line.clone()), row);
        }
    }
}
