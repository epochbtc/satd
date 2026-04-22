use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::state::{AppState, NodeWarning, WarningSeverity};

/// Render the warnings modal as a centered overlay. Called AFTER any
/// underlying view has drawn, so it paints over everything.
///
/// Color: red if any Error-severity warning is active, yellow if only
/// Warn. No bottom-line of the TUI is a normal place for these —
/// every warning in the list represents an operational issue worth
/// fixing, not a notice to get used to.
pub fn draw(f: &mut Frame, state: &AppState) {
    let visible: Vec<&NodeWarning> = state.visible_warnings();
    if visible.is_empty() {
        return;
    }

    let highest_severity = visible
        .iter()
        .map(|w| w.severity)
        .max_by_key(|s| match s {
            WarningSeverity::Error => 1,
            WarningSeverity::Warn => 0,
        })
        .unwrap_or(WarningSeverity::Warn);

    let (border_color, title, title_color) = match highest_severity {
        WarningSeverity::Error => (Color::Red, " ⚠ NODE ERROR ", Color::Red),
        WarningSeverity::Warn => (Color::Yellow, " ⚠ NODE WARNING ", Color::Yellow),
    };

    let area = centered_rect(80, 70, f.area());
    f.render_widget(Clear, area); // wipe what's underneath

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color).add_modifier(Modifier::BOLD))
        .title(Span::styled(
            title.to_string(),
            Style::default()
                .fg(title_color)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(inner.inner(Margin { horizontal: 1, vertical: 1 }));

    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(Span::styled(
        format!("  {} active operational issue(s):", visible.len()),
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for w in &visible {
        lines.extend(warning_lines(w, now));
        lines.push(Line::from(""));
    }

    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(para, chunks[0]);

    let footer = Line::from(vec![
        Span::styled("a", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled(": acknowledge + dismiss for this session    ", Style::default().fg(Color::Gray)),
        Span::styled("w", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled(": toggle this modal", Style::default().fg(Color::Gray)),
    ])
    .alignment(Alignment::Center);
    f.render_widget(Paragraph::new(footer), chunks[1]);
}

fn warning_lines(w: &NodeWarning, now_unix: u64) -> Vec<Line<'static>> {
    let (sev_color, sev_label) = match w.severity {
        WarningSeverity::Error => (Color::Red, "ERROR"),
        WarningSeverity::Warn => (Color::Yellow, "WARN "),
    };
    let age = now_unix.saturating_sub(w.first_seen_unix_secs);
    let age_str = format_secs_ago(age);
    vec![
        Line::from(vec![
            Span::styled("  [", Style::default().fg(Color::DarkGray)),
            Span::styled(
                sev_label.to_string(),
                Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled("] ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                w.id.clone(),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   first seen {} ago · ×{}", age_str, w.count),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("    ", Style::default()),
            Span::styled(w.message.clone(), Style::default().fg(Color::White)),
        ]),
    ]
}

fn format_secs_ago(s: u64) -> String {
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m {}s", s / 60, s % 60)
    } else if s < 86400 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d {}h", s / 86400, (s % 86400) / 3600)
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
