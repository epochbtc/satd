use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Sparkline};

use crate::state::AppState;
use crate::ui::{format_bytes_rate, format_duration, format_num, peer_table, render_block_map};

pub fn draw(f: &mut Frame, state: &AppState) {
    let size = f.area();

    // Main layout: title(1) + progress(5) + blockmap(10) + sparklines+stats(7) + peers(rest) + footer(1)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),   // title
            Constraint::Length(5),   // progress
            Constraint::Length(12),  // block map
            Constraint::Length(9),   // sparklines + stats
            Constraint::Min(5),     // peers
            Constraint::Length(1),   // footer
        ])
        .split(size);

    // Title bar
    let title = Line::from(vec![
        Span::styled(" satd IBD ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!(" {} ", state.chain_name),
            Style::default().fg(Color::White),
        ),
        Span::styled(" v0.1.0 ", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(title), chunks[0]);

    // Progress block
    draw_progress(f, chunks[1], state);

    // Block map
    draw_block_map(f, chunks[2], state);

    // Sparklines + Stats
    draw_sparklines_and_stats(f, chunks[3], state);

    // Peers
    let peer_title = format!("Peers ({} connected)", state.connections);
    let ibd_stats = state.ibd_bitmap.as_ref().map(|b| b.peer_stats.as_slice());
    let table = peer_table(&state.peers, &state.peer_rates, ibd_stats, state.selected_peer, &peer_title);
    f.render_widget(table, chunks[4]);

    // Footer
    let footer = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::White)),
        Span::styled(": quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled("1/2", Style::default().fg(Color::White)),
        Span::styled(": switch view  ", Style::default().fg(Color::DarkGray)),
        Span::raw("\u{2191}\u{2193}"),
        Span::styled(": scroll peers", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(footer), chunks[5]);
}

fn draw_progress(f: &mut Frame, area: Rect, state: &AppState) {
    let progress = if state.headers > 0 {
        state.blocks as f64 / state.headers as f64
    } else {
        0.0
    };

    let label = format!(
        "{} / {}  {:.1}%",
        format_num(state.blocks as u64),
        format_num(state.headers as u64),
        progress * 100.0
    );

    let eta_str = state.eta_secs
        .map(|s| format!("ETA: {}", format_duration(s)))
        .unwrap_or_else(|| "ETA: --".to_string());

    let stats_line = format!(
        "{}   blk/s: {:.0}   hdr/s: {:.0}   dl: {}",
        eta_str,
        state.blocks_per_sec,
        state.headers_per_sec,
        format_bytes_rate(state.download_rate_bytes),
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Block Sync ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height >= 3 {
        let gauge_area = Rect { height: 1, y: inner.y, ..inner };
        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
            .ratio(progress.min(1.0))
            .label(Span::styled(&label, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)));
        f.render_widget(gauge, gauge_area);

        let stats_area = Rect { y: inner.y + 2, height: 1, ..inner };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(stats_line, Style::default().fg(Color::Yellow)))),
            stats_area,
        );
    }
}

fn draw_block_map(f: &mut Frame, area: Rect, state: &AppState) {
    let bitmap = match &state.ibd_bitmap {
        Some(b) => b,
        None => {
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(
                    " Block Map ",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ));
            f.render_widget(block, area);
            return;
        }
    };

    let bpc = if bitmap.target_height > 0 {
        let cells = (area.width.saturating_sub(4) as u32) * (area.height.saturating_sub(4) as u32);
        if cells > 0 { bitmap.target_height / cells } else { 1 }
    } else {
        1
    }.max(1);

    let title = format!(
        " Block Map -- {} / {} -- each \u{2588} \u{2248} {} blocks ",
        format_num(bitmap.connect_cursor as u64),
        format_num(bitmap.target_height as u64),
        bpc,
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title,
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    // Reserve last line for legend
    let map_height = inner.height.saturating_sub(1);
    let lines = render_block_map(bitmap, inner.width, map_height);

    for (i, line) in lines.iter().enumerate() {
        if i < map_height as usize {
            let line_area = Rect {
                x: inner.x,
                y: inner.y + i as u16,
                width: inner.width,
                height: 1,
            };
            f.render_widget(Paragraph::new(line.clone()), line_area);
        }
    }

    // Legend
    let legend_area = Rect {
        x: inner.x,
        y: inner.y + map_height,
        width: inner.width,
        height: 1,
    };
    let legend = Line::from(vec![
        Span::styled("\u{2588}", Style::default().fg(Color::Green)),
        Span::styled(" connected  ", Style::default().fg(Color::DarkGray)),
        Span::styled("\u{2591}", Style::default().fg(Color::Cyan)),
        Span::styled(" downloaded  ", Style::default().fg(Color::DarkGray)),
        Span::styled("\u{2593}", Style::default().fg(Color::Yellow)),
        Span::styled(" in-flight  ", Style::default().fg(Color::DarkGray)),
        Span::styled("\u{00B7}", Style::default().fg(Color::DarkGray)),
        Span::styled(" pending", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(legend), legend_area);
}

fn draw_sparklines_and_stats(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(55),
            Constraint::Percentage(45),
        ])
        .split(area);

    // Sparklines
    let spark_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Sync Rate ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    let spark_inner = spark_block.inner(chunks[0]);
    f.render_widget(spark_block, chunks[0]);

    if spark_inner.height >= 4 {
        // Blocks/sec sparkline
        let bps_data: Vec<u64> = state.bps_history.iter().map(|v| *v as u64).collect();
        let peak_bps = bps_data.iter().copied().max().unwrap_or(0);
        let bps_spark = Sparkline::default()
            .data(&bps_data)
            .style(Style::default().fg(Color::Yellow));
        let spark1_area = Rect { height: (spark_inner.height / 2).saturating_sub(1).max(1), ..spark_inner };
        f.render_widget(bps_spark, spark1_area);

        let bps_label = Rect { y: spark1_area.y + spark1_area.height, height: 1, ..spark_inner };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    format!("peak: {}    now: {:.0}", peak_bps, state.blocks_per_sec),
                    Style::default().fg(Color::DarkGray),
                ),
            ])),
            bps_label,
        );

        // Download rate sparkline
        let dl_data: Vec<u64> = state.dl_history.iter().map(|v| (*v / 1024.0) as u64).collect();
        let dl_spark = Sparkline::default()
            .data(&dl_data)
            .style(Style::default().fg(Color::Cyan));
        let spark2_y = bps_label.y + 1;
        let spark2_h = spark_inner.height.saturating_sub(spark2_y - spark_inner.y).saturating_sub(1).max(1);
        let spark2_area = Rect { y: spark2_y, height: spark2_h, ..spark_inner };
        f.render_widget(dl_spark, spark2_area);

        let dl_label = Rect { y: spark2_y + spark2_h, height: 1, ..spark_inner };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("dl: {}", format_bytes_rate(state.download_rate_bytes)),
                Style::default().fg(Color::DarkGray),
            ))),
            dl_label,
        );
    }

    // Stats panel
    let stats_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Stats ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    let stats_inner = stats_block.inner(chunks[1]);
    f.render_widget(stats_block, chunks[1]);

    let headers_val = format_num(state.headers as u64);
    let connected_val = format_num(state.blocks as u64);
    let (stored, inflight, remaining) = if let Some(ref bm) = state.ibd_bitmap {
        (
            format_num(bm.downloaded as u64),
            format_num(bm.in_flight as u64),
            format_num(bm.pending as u64),
        )
    } else {
        ("-".into(), "-".into(), "-".into())
    };

    let stats_lines = [
        Line::from(vec![
            Span::styled("Headers:    ", Style::default().fg(Color::Gray)),
            Span::styled(headers_val, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Connected:  ", Style::default().fg(Color::Gray)),
            Span::styled(connected_val, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Stored:     ", Style::default().fg(Color::Gray)),
            Span::styled(stored, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("In-Flight:  ", Style::default().fg(Color::Gray)),
            Span::styled(inflight, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Remaining:  ", Style::default().fg(Color::Gray)),
            Span::styled(remaining, Style::default().fg(Color::White)),
        ]),
    ];

    for (i, line) in stats_lines.iter().enumerate() {
        if i < stats_inner.height as usize {
            let line_area = Rect {
                x: stats_inner.x,
                y: stats_inner.y + i as u16,
                width: stats_inner.width,
                height: 1,
            };
            f.render_widget(Paragraph::new(line.clone()), line_area);
        }
    }
}
