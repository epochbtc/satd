use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::state::{AppState, ReorgEntry};
use crate::ui::{format_duration, format_hash};

pub fn draw(f: &mut Frame, state: &AppState) {
    let size = f.area();

    let title = format!(" Reorg History ({} recorded, last 7 days) ", state.reorg_history.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title,
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(size);

    let inner = block.inner(chunks[0]);
    f.render_widget(block, chunks[0]);

    let lines = if state.reorg_history.is_empty() {
        vec![Line::from(Span::styled(
            "  No reorgs recorded in the last 7 days.",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        state
            .reorg_history
            .iter()
            .take(40)
            .flat_map(|r| entry_lines(r, now))
            .collect()
    };

    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(para, inner);

    let footer = Line::from(vec![
        Span::styled("r", Style::default().fg(Color::White)),
        Span::styled("/", Style::default().fg(Color::DarkGray)),
        Span::styled("q", Style::default().fg(Color::White)),
        Span::styled("/", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::White)),
        Span::styled(": close reorgs", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(footer), chunks[1]);
}

fn entry_lines(r: &ReorgEntry, now_unix: u64) -> Vec<Line<'static>> {
    let ago = format_duration(now_unix.saturating_sub(r.ts_unix_secs));
    let depth_color = match r.depth {
        1 => Color::Yellow,
        2..=3 => Color::LightRed,
        _ => Color::Red,
    };
    vec![
        Line::from(vec![
            Span::styled("  depth ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{:<3}", r.depth),
                Style::default().fg(depth_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" │ {:>8} ago │ fork at ", ago), Style::default().fg(Color::Gray)),
            Span::styled(r.fork_height.to_string(), Style::default().fg(Color::White)),
            Span::styled(
                format!(" │ -{} +{} blocks", r.disconnected_len, r.reconnected_len),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled("          old: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_hash(&r.old_tip), Style::default().fg(Color::Red)),
            Span::styled("   new: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_hash(&r.new_tip), Style::default().fg(Color::Green)),
        ]),
        Line::from(""),
    ]
}
