pub mod chain;
pub mod help;
pub mod ibd;
pub mod mempool;
pub mod reorgs;
pub mod steady;
pub mod warnings;

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Cell};
use ratatui::layout::Constraint;

/// Format bytes as human-readable (e.g., "1.23 MB").
pub fn format_bytes(n: u64) -> String {
    if n < 1_024 {
        format!("{} B", n)
    } else if n < 1_048_576 {
        format!("{:.1} KB", n as f64 / 1_024.0)
    } else if n < 1_073_741_824 {
        format!("{:.2} MB", n as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", n as f64 / 1_073_741_824.0)
    }
}

/// Format a block hash for display (first 8 + ... + last 4 chars).
pub fn format_hash(h: &str) -> String {
    if h.len() > 16 {
        format!("{}...{}", &h[..8], &h[h.len()-4..])
    } else {
        h.to_string()
    }
}

/// Format duration in seconds to human-readable.
pub fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

/// Format satoshis as BTC string.
pub fn format_btc(sats: u64) -> String {
    format!("{:.4} BTC", sats as f64 / 100_000_000.0)
}

/// Format hash rate.
pub fn format_hashrate(hps: f64) -> String {
    if hps < 1_000.0 {
        format!("{:.1} H/s", hps)
    } else if hps < 1_000_000.0 {
        format!("{:.1} KH/s", hps / 1_000.0)
    } else if hps < 1_000_000_000.0 {
        format!("{:.1} MH/s", hps / 1_000_000.0)
    } else if hps < 1_000_000_000_000.0 {
        format!("{:.1} GH/s", hps / 1_000_000_000.0)
    } else if hps < 1_000_000_000_000_000.0 {
        format!("{:.1} TH/s", hps / 1_000_000_000_000.0)
    } else {
        format!("{:.1} PH/s", hps / 1_000_000_000_000_000.0)
    }
}

/// Format number with commas (e.g., 1,234,567).
pub fn format_num(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Build a peer table for either view.
pub fn peer_table<'a>(
    peers: &'a [serde_json::Value],
    ibd_stats: Option<&'a [crate::state::PeerDownloadStat]>,
    peer_dl_rates: &'a std::collections::HashMap<u64, f64>,
    selected: usize,
    title: &'a str,
) -> Table<'a> {
    let (header, widths) = if ibd_stats.is_some() {
        (
            Row::new(vec!["Addr", "Agent", "Recv", "Assigned", "Rate"])
                .style(Style::default().fg(Color::Cyan)),
            vec![
                Constraint::Min(22),
                Constraint::Min(20),
                Constraint::Min(10),
                Constraint::Min(8),
                Constraint::Min(10),
            ],
        )
    } else {
        (
            Row::new(vec!["Addr", "Agent", "Height", "Recv"])
                .style(Style::default().fg(Color::Cyan)),
            vec![
                Constraint::Min(22),
                Constraint::Min(22),
                Constraint::Min(12),
                Constraint::Min(12),
            ],
        )
    };

    let ibd_map: std::collections::HashMap<u64, &crate::state::PeerDownloadStat> = ibd_stats
        .map(|stats| stats.iter().map(|s| (s.peer_id, s)).collect())
        .unwrap_or_default();

    let rows: Vec<Row> = peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let addr = p.get("addr").and_then(|a| a.as_str()).unwrap_or("-");
            let agent = p.get("subver").and_then(|a| a.as_str()).unwrap_or("-");
            let peer_id = p.get("id").and_then(|id| id.as_u64()).unwrap_or(0);

            let cells = if ibd_stats.is_some() {
                let ibd = ibd_map.get(&peer_id);
                let rate = peer_dl_rates.get(&peer_id).copied().unwrap_or(0.0);
                let rate_str = if rate > 0.1 { format!("{:.1} blk/s", rate) } else { "-".into() };
                vec![
                    Cell::from(addr.to_string()),
                    Cell::from(agent.to_string()),
                    Cell::from(ibd.map(|s| format_num(s.blocks_received)).unwrap_or("-".into())),
                    Cell::from(ibd.map(|s| s.assigned.to_string()).unwrap_or("-".into())),
                    Cell::from(rate_str),
                ]
            } else {
                let height = p.get("synced_headers").and_then(|h| h.as_u64())
                    .or_else(|| p.get("startingheight").and_then(|h| h.as_u64()))
                    .unwrap_or(0);
                let recv = p.get("bytesrecv").and_then(|b| b.as_u64()).unwrap_or(0);
                vec![
                    Cell::from(addr.to_string()),
                    Cell::from(agent.to_string()),
                    Cell::from(format_num(height)),
                    Cell::from(format_bytes(recv)),
                ]
            };

            let style = if i == selected {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            Row::new(cells).style(style)
        })
        .collect();

    Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(
                    format!(" {} ", title),
                    Style::default().fg(Color::Cyan).add_modifier(ratatui::style::Modifier::BOLD),
                )),
        )
}

/// Render the block map grid for IBD view.
pub fn render_block_map(
    bitmap: &crate::state::IbdBitmap,
    width: u16,
    rows: u16,
) -> Vec<Line<'static>> {
    let total_blocks = bitmap.target_height;
    let usable_width = width.saturating_sub(2) as u32; // borders
    if usable_width == 0 || rows == 0 || total_blocks == 0 {
        return vec![];
    }

    let total_cells = usable_width * rows as u32;
    let blocks_per_cell = (total_blocks as f64 / total_cells as f64).max(1.0);

    let mut lines = Vec::with_capacity(rows as usize);

    for row in 0..rows {
        let mut spans = Vec::new();
        for col in 0..usable_width {
            let cell_idx = row as u32 * usable_width + col;
            let block_start = (cell_idx as f64 * blocks_per_cell) as u32;
            let block_end = ((cell_idx as f64 + 1.0) * blocks_per_cell) as u32;

            if block_end == 0 || block_start >= total_blocks {
                spans.push(Span::styled(" ", Style::default()));
                continue;
            }

            // Determine dominant state for this cell
            let mid = (block_start + block_end) / 2;

            let (ch, color) = if mid <= bitmap.connect_cursor {
                // Connected
                ("\u{2588}", Color::Green) // full block
            } else if mid >= bitmap.bitmap_start {
                let idx = (mid - bitmap.bitmap_start) as usize;
                match bitmap.bitmap.get(idx).copied().unwrap_or(0) {
                    3 => ("\u{2591}", Color::Cyan),    // light shade - downloaded
                    2 => ("\u{2593}", Color::Yellow),  // dark shade - in-flight
                    1 => ("\u{00B7}", Color::DarkGray),// middle dot - pending
                    _ => ("\u{00B7}", Color::DarkGray),// middle dot - not requested
                }
            } else {
                ("\u{2588}", Color::Green)
            };

            spans.push(Span::styled(ch, Style::default().fg(color)));
        }
        lines.push(Line::from(spans));
    }

    lines
}

/// Render the connecting screen.
pub fn connecting_paragraph<'a>(stale: bool, startup_status: Option<&str>) -> Paragraph<'a> {
    let msg = if let Some(status) = startup_status {
        format!("satd is starting: {}", status)
    } else if stale {
        "Connection to satd lost. Reconnecting...".to_string()
    } else {
        "Connecting to satd...".to_string()
    };
    Paragraph::new(Line::from(vec![
        Span::styled(msg, Style::default().fg(Color::Yellow)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " sat-tui ",
                Style::default().fg(Color::Cyan).add_modifier(ratatui::style::Modifier::BOLD),
            )),
    )
}

/// Render a panel with a "loading..." message inside.
pub fn render_loading_panel(f: &mut ratatui::Frame, area: ratatui::layout::Rect, title: &str) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title.to_string(),
            Style::default().fg(Color::Cyan).add_modifier(ratatui::style::Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height > 0 {
        let loading = Paragraph::new(Line::from(Span::styled(
            "loading...",
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(loading, inner);
    }
}
