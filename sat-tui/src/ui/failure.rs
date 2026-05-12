use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::state::{AppState, RpcFailure};

/// Render a centred red modal for hard RPC failures. Sits on top of
/// every other view so the operator can't miss it — replaces the
/// silent "Connecting..." screen for cases that won't self-heal.
///
/// AuthFailed fires immediately (the cookie is almost certainly
/// unreadable or stale — operator action required). Other failures
/// wait 5s before surfacing so transient restart blips don't flash
/// a modal at every satd reload.
pub fn draw(f: &mut Frame, state: &AppState) {
    let Some(rec) = state.last_failure.as_ref() else {
        return;
    };

    let age = rec.first_seen.elapsed();
    let show_immediately = matches!(rec.kind, RpcFailure::AuthFailed);
    if !show_immediately && age.as_secs() < 5 {
        return;
    }

    let (title, headline, hints): (&str, &str, &[&str]) = match rec.kind {
        RpcFailure::AuthFailed => (
            " ✗ RPC AUTHENTICATION FAILED ",
            "satd rejected our credentials (HTTP 401).",
            &[
                "• Cookie file unreadable, missing, or stale.",
                "• If running as a different user than satd, add yourself to the",
                "  `satd` group, then start a NEW shell (group memberships only",
                "  refresh on login): `sudo usermod -aG satd $USER`.",
                "• If using --rpcuser/--rpcpassword, confirm they match satd's",
                "  config exactly.",
                "• Confirm cookie path with: `ls -l <datadir>/.cookie`.",
            ],
        ),
        RpcFailure::ConnectionFailed => (
            " ✗ RPC CONNECTION FAILED ",
            "Cannot reach satd's JSON-RPC endpoint.",
            &[
                "• Is satd running? `systemctl status satd`",
                "• Is --rpcport correct? Default 8332, signet 38332, testnet 18332.",
                "• Is satd bound to a different host than --rpcconnect?",
                "  (default 127.0.0.1).",
            ],
        ),
        RpcFailure::Timeout => (
            " ⏳ RPC TIMEOUT ",
            "satd accepted the connection but didn't respond in 30s.",
            &[
                "• Heavy IBD validation can briefly block the RPC thread.",
                "• If persistent, check `journalctl -u satd.service` for stalls.",
            ],
        ),
        RpcFailure::Other => (
            " ✗ RPC ERROR ",
            "Unexpected RPC failure.",
            &[],
        ),
    };

    let area = centered_rect(80, 60, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        .title(Span::styled(
            title.to_string(),
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2)])
        .split(inner.inner(Margin { horizontal: 2, vertical: 1 }));

    let mut lines: Vec<Line<'static>> = vec![
        Line::from(Span::styled(
            headline.to_string(),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("details: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                rec.message.clone(),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled("failing for ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format_secs(age.as_secs()),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ];
    if !hints.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Things to check:",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )));
        for hint in hints {
            lines.push(Line::from(Span::styled(
                hint.to_string(),
                Style::default().fg(Color::Gray),
            )));
        }
    }

    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(para, chunks[0]);

    let footer = Line::from(vec![
        Span::styled(
            "modal clears automatically once any RPC succeeds  ·  ",
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled("q", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled(": quit", Style::default().fg(Color::Gray)),
    ])
    .alignment(Alignment::Center);
    f.render_widget(Paragraph::new(footer), chunks[1]);
}

fn format_secs(s: u64) -> String {
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
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
