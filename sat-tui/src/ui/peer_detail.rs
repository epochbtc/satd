//! The Peer detail overlay (`Enter` on a peers-table row, `Esc` closes):
//! connection type and transport, the observed family against the claimed
//! agent, each flag with its evidence, and the behaviour counters.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::behavior::{evidence_line, fingerprint_line, flags_cell};
use crate::nap::printable;
use crate::state::AppState;
use crate::ui::{flags_color, format_duration};

fn field(key: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {key:<12}"), Style::default().fg(Color::Cyan)),
        Span::styled(value, Style::default().fg(Color::White)),
    ])
}

fn heading(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_string(),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ))
}

/// The overlay's lines for peer `id`. Every string from the node is
/// escaped: the behaviour parser escapes its own, and the transport and
/// user agent from `getpeerinfo` are escaped here.
pub fn lines(state: &AppState, id: u64) -> Vec<Line<'static>> {
    let info = state
        .peers
        .iter()
        .find(|p| p.get("id").and_then(|i| i.as_u64()) == Some(id));
    let Some(b) = state.behavior_for(id) else {
        // Connected since the last `getpeerbehavior` poll, or gone.
        let msg = if info.is_some() {
            format!("  peer {id} has no behaviour data yet; it arrives within about 5 s")
        } else {
            format!("  peer {id} is no longer connected")
        };
        return vec![Line::from(Span::styled(
            msg,
            Style::default().fg(Color::DarkGray),
        ))];
    };
    let info_str = |key: &str| {
        info.and_then(|p| p.get(key))
            .and_then(|v| v.as_str())
            .map(printable)
    };
    let agent = info_str("subver").unwrap_or_else(|| b.subver.clone());
    let fp_style = if b.fingerprint.is_mismatch() {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::White)
    };

    let mut out = vec![
        field("connection", b.connection_type.clone()),
        field(
            "transport",
            info_str("transport_protocol_type").unwrap_or_else(|| "-".into()),
        ),
        field("connected", format_duration(b.session_secs)),
        field(
            "agent",
            if agent.is_empty() {
                "(none)".into()
            } else {
                agent
            },
        ),
        Line::from(vec![
            Span::styled(
                format!("  {:<12}", "observed"),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(fingerprint_line(b), fp_style),
        ]),
        field(
            "handshake",
            if b.handshake.is_empty() {
                "-".into()
            } else {
                b.handshake.join(" ")
            },
        ),
    ];
    match &b.alt_slot {
        Some(crate::behavior::AltSlot::Matched { rule, trust }) => {
            out.push(field("alt-slot", format!("{rule} (user agent {trust})")));
        }
        Some(crate::behavior::AltSlot::Fallback) => {
            out.push(field(
                "alt-slot",
                "fallback: an ordinary peer until a match turns up".into(),
            ));
        }
        None => {}
    }
    out.push(Line::from(""));

    let (codes, tone) = flags_cell(b);
    out.push(Line::from(vec![
        Span::styled(
            "Flags ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            codes,
            Style::default()
                .fg(flags_color(tone))
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    if !b.evaluated {
        out.push(Line::from(Span::styled(
            "  not judged yet",
            Style::default().fg(Color::DarkGray),
        )));
    } else if b.flags.is_empty() {
        out.push(Line::from(Span::styled(
            "  none",
            Style::default().fg(Color::DarkGray),
        )));
    }
    for f in &b.flags {
        out.push(Line::from(vec![
            Span::styled(
                format!("  {} {:<20}", f.code, f.name),
                Style::default().fg(Color::White),
            ),
            Span::styled(evidence_line(f), Style::default().fg(Color::Gray)),
        ]));
    }
    out.push(Line::from(""));
    out.push(heading("Counters"));
    for (k, v) in &b.counters {
        out.push(Line::from(vec![
            Span::styled(format!("  {k:<28}"), Style::default().fg(Color::Cyan)),
            Span::styled(v.clone(), Style::default().fg(Color::White)),
        ]));
    }
    out
}

/// Draw the overlay over the active peers view, when one is open.
pub fn draw(f: &mut Frame, state: &AppState) {
    let Some(id) = state.shown_peer_detail() else {
        return;
    };
    let size = f.area();
    let width = size.width.saturating_sub(4).min(100);
    let height = size.height.saturating_sub(2);
    let area = Rect {
        x: size.x + (size.width - width) / 2,
        y: size.y + (size.height - height) / 2,
        width,
        height,
    };
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            format!(" Peer {id} detail "),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Esc: close ",
            Style::default().fg(Color::DarkGray),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(
        Paragraph::new(lines(state, id)).wrap(Wrap { trim: false }),
        inner,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ViewMode;
    use serde_json::json;

    fn text(lines: &[Line<'_>]) -> Vec<String> {
        lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    /// The overlay states connection type, transport, observed family
    /// against the claimed agent, each flag with its evidence, and the
    /// counters.
    #[test]
    fn overlay_shows_fingerprint_flags_and_counters() {
        let mut st = AppState::new();
        st.force_mode = Some(ViewMode::Steady);
        st.peers = vec![
            json!({"id": 3, "subver": "/Satoshi:27.0.0/\x1b", "transport_protocol_type": "v2"}),
        ];
        st.update_peer_behavior(crate::behavior::classify(Ok(
            crate::behavior::tests::reply(),
        )));
        let t = text(&lines(&st, 3));
        let has = |needle: &str| t.iter().any(|l| l.contains(needle));
        assert!(has("connection  outbound-full-relay"), "{t:?}");
        assert!(has("transport   v2"), "{t:?}");
        assert!(
            has("agent       /Satoshi:27.0.0/?"),
            "the agent is escaped: {t:?}"
        );
        assert!(
            has("observed    btcd, but the user agent names core"),
            "{t:?}"
        );
        assert!(has("handshake   version verack sendaddrv2"), "{t:?}");
        assert!(
            has("F fingerprint-mismatch") && has("claimed=core observed=btcd"),
            "{t:?}"
        );
        assert!(has("inv_tx_in") && has("version.start_height"), "{t:?}");

        assert!(text(&lines(&st, 99))[0].contains("no longer connected"));
        // Listed by getpeerinfo, not yet judged: not "gone".
        st.peers.push(json!({"id": 42}));
        assert!(
            text(&lines(&st, 42))[0].contains("no behaviour data yet"),
            "{:?}",
            text(&lines(&st, 42))
        );
    }
}
