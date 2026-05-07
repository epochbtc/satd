//! Rich startup-progress panel.
//!
//! Rendered when the node is in pre-RPC startup (DB open, reindex,
//! chainstate replay). Shows the active phase, a progress bar, and
//! elapsed / rate / ETA derived from a rolling sample window kept by
//! `AppState::update_startup`.
//!
//! ETA is intentionally per-phase, not whole-startup: phase 1 (header
//! scan) and phase 2 (block replay) have very different per-item costs,
//! so a unified estimate would be misleading until phase 2 dominates.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};

use crate::state::AppState;
use crate::ui::{format_duration, format_num};

pub fn draw(f: &mut Frame, st: &AppState) {
    let area = f.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " sat-tui — satd starting ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let status = match st.startup_status.as_ref() {
        Some(s) => s,
        None => return,
    };

    // Top-line summary, gauge, then per-stat lines.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // header
            Constraint::Length(1), // spacer
            Constraint::Length(1), // gauge
            Constraint::Length(1), // spacer
            Constraint::Min(0),    // stats
        ])
        .split(inner);

    // Header: phase title + raw count.
    let phase_title = phase_label(&status.phase);
    let count_line = if status.total > 0 {
        format!("{} / {}", format_num(status.current), format_num(status.total))
    } else {
        format!("{} (total tbd)", format_num(status.current))
    };
    let header = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            phase_title,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled(status.message.clone(), Style::default().fg(Color::Gray)),
            Span::raw("  —  "),
            Span::styled(count_line, Style::default().fg(Color::White)),
        ]),
    ]);
    f.render_widget(header, chunks[0]);

    // Progress gauge.
    let pct = if status.total > 0 {
        ((status.current as f64 / status.total as f64) * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };
    let gauge_label = if status.total > 0 {
        format!("{:.1}%", pct)
    } else {
        "—".to_string()
    };
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(Color::Green).bg(Color::Black))
        .label(gauge_label)
        .ratio(pct / 100.0);
    f.render_widget(gauge, chunks[2]);

    // Stats: elapsed | rate | ETA. ETA is suppressed outside the long
    // phase (`reindex_connect`) — phase 1 finishes in seconds, an ETA
    // there is noise.
    let elapsed = st
        .startup_phase_started_at
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    let total_elapsed = st
        .startup_started_at
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    let rate = st.startup_rate();
    let eta = if status.phase == "reindex_connect" {
        st.startup_eta_secs()
    } else {
        None
    };

    let mut stat_lines: Vec<Line> = Vec::new();
    stat_lines.push(stat_line(
        "Phase elapsed",
        format_duration(elapsed),
        Color::Cyan,
    ));
    if total_elapsed != elapsed {
        stat_lines.push(stat_line(
            "Total elapsed",
            format_duration(total_elapsed),
            Color::Cyan,
        ));
    }
    let rate_str = match rate {
        Some(r) if r >= 1.0 => format!("{:.0} blocks/s", r),
        Some(r) => format!("{:.2} blocks/s", r),
        None => "—".to_string(),
    };
    stat_lines.push(stat_line("Rate", rate_str, Color::Green));
    let eta_str = match eta {
        Some(s) => format_duration(s),
        None => "—".to_string(),
    };
    stat_lines.push(stat_line("ETA (phase)", eta_str, Color::Yellow));

    if !st.startup_phase.is_empty() {
        stat_lines.push(stat_line(
            "Phase id",
            st.startup_phase.clone(),
            Color::DarkGray,
        ));
    }

    stat_lines.push(Line::from(""));
    stat_lines.push(Line::from(Span::styled(
        "Press q to quit. The full TUI will load once satd finishes startup.",
        Style::default().fg(Color::DarkGray),
    )));

    let stats_area = pad_left(chunks[4], 2);
    f.render_widget(Paragraph::new(stat_lines), stats_area);
}

fn stat_line(label: &str, value: String, value_color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{:<14}", label), Style::default().fg(Color::Gray)),
        Span::styled(value, Style::default().fg(value_color)),
    ])
}

fn phase_label(phase: &str) -> String {
    match phase {
        "opening_db" => "Opening database".to_string(),
        "clearing_db" => "Clearing database for reindex".to_string(),
        "chain_init" => "Initializing chain state".to_string(),
        "reindex_scan" => "Reindex — phase 1/2: scanning block files".to_string(),
        "reindex_connect" => "Reindex — phase 2/2: replaying blocks".to_string(),
        "reindex_chainstate" => "Reindex chainstate".to_string(),
        "" => "Starting".to_string(),
        other => other.to_string(),
    }
}

fn pad_left(area: Rect, pad: u16) -> Rect {
    if area.width <= pad {
        return area;
    }
    Rect {
        x: area.x + pad,
        y: area.y,
        width: area.width - pad,
        height: area.height,
    }
}
