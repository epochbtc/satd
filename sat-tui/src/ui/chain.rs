use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::state::AppState;
use crate::ui::{format_duration, format_hashrate, format_num};

pub fn draw(f: &mut Frame, state: &AppState) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Length(8), // halvings + retarget
            Constraint::Length(8), // supply + security
            Constraint::Length(8), // peer clients + trivia
            Constraint::Min(0),    // filler
            Constraint::Length(1), // footer
        ])
        .split(size);

    draw_title(f, chunks[0], state);
    draw_row_one(f, chunks[1], state);
    draw_row_two(f, chunks[2], state);
    draw_row_three(f, chunks[3], state);
    draw_footer(f, chunks[5]);
}

fn draw_title(f: &mut Frame, area: Rect, state: &AppState) {
    let uptime_str = state
        .uptime_secs
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
        Span::styled(
            " satd ",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" {} ", state.chain_name), Style::default().fg(Color::White)),
        Span::styled(dot_glyph, Style::default().fg(dot_color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{} ", health_label), Style::default().fg(dot_color)),
        Span::styled(crate::ui::VERSION_TAG, Style::default().fg(Color::DarkGray)),
        Span::styled(uptime_str, Style::default().fg(Color::DarkGray)),
        Span::styled(
            " chain & issuance ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" @ #{}", format_num(state.blocks as u64)),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    f.render_widget(Paragraph::new(title), area);
}

fn draw_row_one(f: &mut Frame, area: Rect, state: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    draw_halvings(f, cols[0], state);
    draw_retarget(f, cols[1], state);
}

fn draw_row_two(f: &mut Frame, area: Rect, state: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    draw_supply(f, cols[0], state);
    draw_security(f, cols[1], state);
}

fn draw_row_three(f: &mut Frame, area: Rect, state: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    draw_peer_clients(f, cols[0], state);
    draw_trivia(f, cols[1], state);
}

// ---- Halvings ---------------------------------------------------------------

fn draw_halvings(f: &mut Frame, area: Rect, state: &AppState) {
    let subsidy_btc = state.subsidy_sats() as f64 / 1e8;
    let to_halving = state.blocks_to_halving();
    let halving_eta = format_duration((to_halving as u64) * 600);
    let progress_pct = ((state.blocks % 210_000) as f64 / 210_000.0).clamp(0.0, 1.0);

    let lines = vec![
        info_line("Subsidy Epoch:", &state.subsidy_epoch().to_string()),
        info_line("Subsidy:", &format!("{:.3} BTC", subsidy_btc)),
        info_line("Halving In:", &format!("{} blk", format_num(to_halving as u64))),
        info_line("Halving ETA:", &format!("~{}", halving_eta)),
        progress_line(progress_pct, Color::Green),
    ];
    render_panel(f, area, " Halvings ", &lines);
}

// ---- Difficulty Retarget ---------------------------------------------------

fn draw_retarget(f: &mut Frame, area: Rect, state: &AppState) {
    let to_retarget = state.blocks_to_retarget();
    let retarget_eta = format_duration((to_retarget as u64) * 600);

    let block_time_str = state
        .epoch_avg_block_secs()
        .map(|s| format_duration(s.round() as u64))
        .unwrap_or_else(|| "-".into());

    let change_str = state
        .retarget_change_pct()
        .map(|p| {
            let sign = if p >= 0.0 { "+" } else { "" };
            format!("{}{:.2}%", sign, p)
        })
        .unwrap_or_else(|| "-".into());

    let progress_pct = ((state.blocks % 2016) as f64 / 2016.0).clamp(0.0, 1.0);

    let lines = vec![
        info_line("Blocks to Retarget:", &format_num(to_retarget as u64)),
        info_line("Retarget ETA:", &format!("~{}", retarget_eta)),
        info_line("Block Time (epoch):", &block_time_str),
        info_line(
            "Δ Est:",
            &change_str,
        ),
        progress_line(progress_pct, Color::Cyan),
    ];
    render_panel(f, area, " Difficulty Retarget ", &lines);
}

// ---- Supply / Issuance -----------------------------------------------------

fn draw_supply(f: &mut Frame, area: Rect, state: &AppState) {
    let issued_str = state
        .utxo_total_amount
        .map(|a| format!("{:.0} BTC", a))
        .unwrap_or_else(|| "loading...".into());
    let pct = state.supply_pct_issued();
    let pct_str = pct
        .map(|p| format!("{:.2}%", p * 100.0))
        .unwrap_or_else(|| "-".into());
    let remaining_str = state
        .utxo_total_amount
        .map(|a| format!("{:.0} BTC", (21_000_000.0 - a).max(0.0)))
        .unwrap_or_else(|| "-".into());

    let realized_str = state
        .realized_annual_inflation()
        .map(|p| format!("{:.2}%/yr", p * 100.0))
        .unwrap_or_else(|| "-".into());
    let forward_str = state
        .forward_annual_inflation()
        .map(|p| format!("{:.2}%/yr", p * 100.0))
        .unwrap_or_else(|| "-".into());

    let mut lines = vec![
        info_line("Issued:", &issued_str),
        info_line("% Issued:", &pct_str),
        info_line("Remaining:", &remaining_str),
    ];
    if let Some(p) = pct {
        lines.push(progress_line(p.clamp(0.0, 1.0), Color::Yellow));
    } else {
        lines.push(Line::from(""));
    }
    lines.push(info_line(
        "Inflation:",
        &format!("realized {} / forward {}", realized_str, forward_str),
    ));

    render_panel(f, area, " Supply / Issuance ", &lines);
}

// ---- Chain Security --------------------------------------------------------

fn draw_security(f: &mut Frame, area: Rect, state: &AppState) {
    let bits_str = state
        .chain_work_bits()
        .map(|b| format!("{:.2} bits", b))
        .unwrap_or_else(|| "-".into());

    let rewrite_str = state
        .chain_rewrite_secs()
        .map(format_secs_long)
        .unwrap_or_else(|| "-".into());

    let hashrate_str = state
        .network_hash_ps
        .map(format_hashrate)
        .unwrap_or_else(|| "-".into());

    let lines = vec![
        info_line("Chain Work:", &bits_str),
        info_line("Rewrite at hashrate:", &rewrite_str),
        info_line("Network Hashrate:", &hashrate_str),
        Line::from(""),
        Line::from(Span::styled(
            "  (theoretical: 2^bits / hashrate)",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    render_panel(f, area, " Chain Security ", &lines);
}

// ---- Peer Clients ----------------------------------------------------------

fn draw_peer_clients(f: &mut Frame, area: Rect, state: &AppState) {
    let total: usize = state.peers.len();
    let dist = state.subver_distribution(5);

    let lines: Vec<Line<'static>> = if total == 0 {
        vec![Line::from(Span::styled(
            "  no connected peers",
            Style::default().fg(Color::DarkGray),
        ))]
    } else if dist.is_empty() {
        vec![Line::from(Span::styled(
            "  no user-agent strings reported",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        dist.iter()
            .map(|(name, count)| {
                let pct = (*count as f64 / total as f64) * 100.0;
                Line::from(vec![
                    Span::styled(format!("  {:<24}", truncate(name, 24)), Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{:>3}", count),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        format!("  {:>5.1}%", pct),
                        Style::default().fg(Color::Gray),
                    ),
                ])
            })
            .collect()
    };

    render_panel(f, area, " Peer Clients ", &lines);
}

// ---- Trivia ----------------------------------------------------------------

fn draw_trivia(f: &mut Frame, area: Rect, state: &AppState) {
    let next_halving_block = (state.subsidy_epoch() + 1) * 210_000;
    let next_retarget_block = state.blocks - (state.blocks % 2016) + 2016;
    let secs_to_halving = state.blocks_to_halving() as u64 * 600;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let halving_calendar = format_calendar_eta(now.saturating_add(secs_to_halving));

    let next_subsidy = state.next_subsidy_sats() as f64 / 1e8;
    let lines = vec![
        info_line("Era index:", &state.subsidy_epoch().to_string()),
        info_line("Next halving:", &format!("~{}", halving_calendar)),
        info_line("Next halving block:", &format_num(next_halving_block as u64)),
        info_line("Next retarget block:", &format_num(next_retarget_block as u64)),
        info_line("Next-block subsidy:", &format!("{:.5} BTC", next_subsidy)),
    ];
    render_panel(f, area, " Trivia ", &lines);
}

// ---- Helpers ---------------------------------------------------------------

fn info_line<'a>(label: &'a str, value: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {:<22}", label), Style::default().fg(Color::Gray)),
        Span::styled(value.to_string(), Style::default().fg(Color::White)),
    ])
}

fn progress_line(frac: f64, color: Color) -> Line<'static> {
    let width: usize = 18;
    let filled = ((frac * width as f64).round() as usize).min(width);
    let empty = width - filled;
    let bar = format!(
        "{}{}",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(empty),
    );
    Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(bar, Style::default().fg(color)),
        Span::styled(format!("  {:.1}%", frac * 100.0), Style::default().fg(Color::DarkGray)),
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

fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::White)),
        Span::styled(": quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled("h", Style::default().fg(Color::White)),
        Span::styled(": help  ", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::White)),
        Span::styled(": reorgs  ", Style::default().fg(Color::DarkGray)),
        Span::styled("1/2/3/4", Style::default().fg(Color::White)),
        Span::styled(": view", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(footer), area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Format a long duration in seconds into a compact "Xy Mm" / "Xd Yh" / etc.
fn format_secs_long(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "-".into();
    }
    if secs >= 31_557_600.0 * 1000.0 {
        format!("~{:.1}M yrs", secs / (31_557_600.0 * 1_000_000.0))
    } else if secs >= 31_557_600.0 {
        format!("~{:.1} yrs", secs / 31_557_600.0)
    } else if secs >= 86_400.0 {
        format!("~{:.1} days", secs / 86_400.0)
    } else if secs >= 3600.0 {
        format!("~{:.1} hours", secs / 3600.0)
    } else {
        format!("~{:.0} sec", secs)
    }
}

/// Cheap calendar approximation: "May 2028". Avoids pulling in chrono.
fn format_calendar_eta(unix_secs: u64) -> String {
    let days_total = unix_secs / 86_400;
    // Convert epoch days to (year, month) via the "civil from days" algorithm
    // (Howard Hinnant). Day 0 of this algorithm is 1970-03-01.
    let z = days_total as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let month_name = match m {
        1 => "Jan", 2 => "Feb", 3 => "Mar", 4 => "Apr",
        5 => "May", 6 => "Jun", 7 => "Jul", 8 => "Aug",
        9 => "Sep", 10 => "Oct", 11 => "Nov", _ => "Dec",
    };
    format!("{} {}", month_name, year)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_eta_known_dates() {
        // 2026-04-30 ≈ 1777680000 unix seconds
        let s = format_calendar_eta(1_777_680_000);
        assert!(s.starts_with("Apr 2026") || s.starts_with("May 2026"), "got {}", s);
        // Distant future: 2200-01-01 ≈ 7_258_118_400
        let s2 = format_calendar_eta(7_258_118_400);
        assert!(s2.contains("2200") || s2.contains("2199"), "got {}", s2);
    }

    #[test]
    fn truncate_unicode_safe() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("/Satoshi:25.0.0/", 12), "/Satoshi:25…");
    }

    #[test]
    fn format_secs_long_buckets() {
        assert_eq!(format_secs_long(45.0), "~45 sec");
        assert_eq!(format_secs_long(7200.0), "~2.0 hours");
        assert_eq!(format_secs_long(2.5 * 86_400.0), "~2.5 days");
        let yrs = format_secs_long(2.0 * 31_557_600.0);
        assert!(yrs.contains("yrs"), "got {}", yrs);
    }
}
