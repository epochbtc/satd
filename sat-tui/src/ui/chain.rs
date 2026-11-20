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
    draw_survey(f, chunks[4], state);
    draw_footer(f, chunks[5], state);
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
        Span::styled(state.version_line(), Style::default().fg(Color::DarkGray)),
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
    render_panel(f, area, " Peer Clients ", &peer_client_lines(state));
}

/// The Peer clients panel: peers by observed family while the node serves
/// behaviour data (a mismatch labelled with its claimed family in
/// brackets), then the mismatch count; by user agent otherwise.
pub fn peer_client_lines(state: &AppState) -> Vec<Line<'static>> {
    let row = |name: &str, count: usize, total: usize| {
        let pct = (count as f64 / total.max(1) as f64) * 100.0;
        Line::from(vec![
            Span::styled(format!("  {:<24}", truncate(&crate::nap::printable(name), 24)), Style::default().fg(Color::White)),
            Span::styled(format!("{:>3}", count), Style::default().fg(Color::Cyan)),
            Span::styled(format!("  {:>5.1}%", pct), Style::default().fg(Color::Gray)),
        ])
    };

    if let Some(map) = state.peer_behavior.as_ref().filter(|m| !m.is_empty()) {
        // Six inner lines: four families, `other`, and the mismatch count.
        let total = map.len();
        let mut lines: Vec<Line<'static>> = crate::behavior::family_distribution(map, 4)
            .iter()
            .map(|(name, count)| row(name, *count, total))
            .collect();
        let mismatches = crate::behavior::mismatch_count(map);
        lines.push(Line::from(Span::styled(
            format!("  fingerprint mismatches: {mismatches}"),
            Style::default().fg(if mismatches > 0 { Color::Red } else { Color::DarkGray }),
        )));
        return lines;
    }

    let total: usize = state.peers.len();
    let dist = state.subver_distribution(5);
    if total == 0 {
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
        dist.iter().map(|(name, count)| row(name, *count, total)).collect()
    }
}

// ---- Network Survey --------------------------------------------------------

/// How row four is drawn in the space below row three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurveyRow {
    /// No survey data: the space stays empty.
    Hidden,
    /// Network survey | Survey detail, this many lines tall.
    Panels(u16),
    /// Too short for the panels: one summary line above the footer.
    Line,
}

/// Row four's form for `space` lines below row three, when the panels
/// need `needed` inner lines.
pub fn survey_row(state: &AppState, space: u16, needed: usize) -> SurveyRow {
    if state.peer_survey.is_none() || space == 0 {
        return SurveyRow::Hidden;
    }
    let height = needed as u16 + 2;
    if space >= height { SurveyRow::Panels(height) } else { SurveyRow::Line }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn draw_survey(f: &mut Frame, area: Rect, state: &AppState) {
    let Some(survey) = state.peer_survey.as_ref() else { return };
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let left = survey_left_lines(survey, cols[0].width.saturating_sub(2));
    let right = survey_right_lines(survey, now_unix());
    match survey_row(state, area.height, left.len().max(right.len())) {
        SurveyRow::Hidden => {}
        SurveyRow::Panels(height) => {
            let mut left_area = cols[0];
            let mut right_area = cols[1];
            left_area.height = height;
            right_area.height = height;
            render_panel(f, left_area, " Network Survey ", &left);
            render_panel(f, right_area, " Survey Detail ", &right);
        }
        SurveyRow::Line => {
            let line_area = Rect { y: area.y + area.height - 1, height: 1, ..area };
            let line = Line::from(Span::styled(format!(" {}", survey.summary()), Style::default().fg(Color::Gray)));
            f.render_widget(Paragraph::new(line), line_area);
        }
    }
}

/// The Network survey panel, `width` cells inside its border: the
/// addresses and the window, a bar per family (the eight largest, then
/// `other`), and the non-Core share.
pub fn survey_left_lines(s: &crate::survey::Survey, width: u16) -> Vec<Line<'static>> {
    const LABEL: usize = 14;
    let mut lines = vec![Line::from(Span::styled(
        format!("  {} addrs, last {} d", format_num(s.addresses), crate::survey::WINDOW_DAYS),
        Style::default().fg(Color::White),
    ))];
    if s.addresses == 0 {
        lines.push(Line::from(Span::styled("  no address reached yet", Style::default().fg(Color::DarkGray))));
        return lines;
    }
    // Two-cell indent, label, space, bar, space, `100.0%`.
    let bar_width = (width as usize).saturating_sub(2 + LABEL + 1 + 1 + 6).clamp(4, 30);
    for (name, count) in s.family_bars() {
        let pct = s.pct(count);
        // A family with any record shows at least one cell.
        let filled = ((pct / 100.0 * bar_width as f64).round() as usize).clamp(usize::from(count > 0), bar_width);
        let color = match name.as_str() {
            "core" => Color::Green,
            "unknown" | "other" => Color::DarkGray,
            _ => Color::Yellow,
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {:<width$} ", truncate(&name, LABEL), width = LABEL), Style::default().fg(Color::White)),
            Span::styled("\u{2588}".repeat(filled), Style::default().fg(color)),
            Span::styled("\u{2591}".repeat(bar_width - filled), Style::default().fg(Color::DarkGray)),
            Span::styled(format!(" {:>5.1}%", pct), Style::default().fg(Color::Gray)),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("  non-Core ", Style::default().fg(Color::Gray)),
        Span::styled(format!("{:.1} %", s.non_core_pct()), Style::default().fg(Color::Cyan)),
    ]));
    lines
}

/// The Survey detail panel: v2 and mismatch shares, the five largest
/// autonomous systems, the last survey connection against `now` (Unix
/// seconds), the connection counts and, with probes on, how many
/// addresses carry a probe outcome.
pub fn survey_right_lines(s: &crate::survey::Survey, now: u64) -> Vec<Line<'static>> {
    let row = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("  {:<13}", label), Style::default().fg(Color::Gray)),
            Span::styled(value, Style::default().fg(Color::White)),
        ])
    };
    let mut lines = vec![
        row("v2:", format!("{:.1} % ({})", s.pct(s.v2), format_num(s.v2))),
        row("mismatches:", format!("{:.1} % ({})", s.pct(s.mismatches), format_num(s.mismatches))),
    ];
    if s.top_as.is_empty() {
        let why = if s.addresses == 0 { "none" } else { "none (needs -asmap)" };
        lines.push(row("top AS:", why.into()));
    } else {
        lines.push(row("top AS:", String::new()));
        for (asn, count) in s.top_as.iter().take(crate::survey::TOP_AS) {
            lines.push(row(&format!("  AS{asn}"), format!("{:.1} %", s.pct(*count))));
        }
    }
    lines.push(row("last survey:", s.last_line(now)));
    lines.push(row("connections:", format!("{} ok, {} failed", format_num(s.completed), format_num(s.failed))));
    if s.probes {
        lines.push(row("probed:", format!("{} addrs", format_num(s.probed))));
    }
    lines
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

fn draw_footer(f: &mut Frame, area: Rect, state: &AppState) {
    let footer = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::White)),
        Span::styled(": quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled("h", Style::default().fg(Color::White)),
        Span::styled(": help  ", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::White)),
        Span::styled(": reorgs  ", Style::default().fg(Color::DarkGray)),
        Span::styled(crate::ui::view_keys(state), Style::default().fg(Color::White)),
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

    fn line_text(l: &Line<'_>) -> String {
        l.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    /// With behaviour data the panel counts observed families, a mismatch
    /// under its observed family with the claimed one in brackets, and ends
    /// with the mismatch count; without it, user agents as before.
    #[test]
    fn peer_clients_by_observed_family() {
        let mut st = AppState::new();
        st.peers = vec![
            serde_json::json!({"id": 3, "subver": "/Satoshi:27.0.0/"}),
            serde_json::json!({"id": 7, "subver": "/bitcoin-seeder:0.01/"}),
        ];
        let before: Vec<String> = peer_client_lines(&st).iter().map(line_text).collect();
        assert_eq!(before.len(), 2);
        assert!(before[0].contains("/Satoshi:27.0.0/") || before[1].contains("/Satoshi:27.0.0/"));
        assert!(!before.iter().any(|l| l.contains("mismatches")));

        st.update_peer_behavior(crate::behavior::classify(Ok(crate::behavior::tests::reply())));
        let after: Vec<String> = peer_client_lines(&st).iter().map(line_text).collect();
        assert!(after.iter().any(|l| l.contains("btcd [core]") && l.contains("1")), "{after:?}");
        assert!(after.iter().any(|l| l.contains("bitcoin-seeder")), "{after:?}");
        assert!(!after.iter().any(|l| l.contains("/Satoshi:")), "{after:?}");
        assert_eq!(after.last().map(String::as_str), Some("  fingerprint mismatches: 1"));
        assert!(after.len() <= 6, "fits the panel's six lines: {after:?}");

        // A node without the method: back to user agents.
        let mnf = crate::rpc::RpcError::Rpc {
            code: crate::rpc::JSONRPC_METHOD_NOT_FOUND,
            message: "Method not found".into(),
        };
        st.update_peer_behavior(crate::behavior::classify(Err(mnf)));
        let off: Vec<String> = peer_client_lines(&st).iter().map(line_text).collect();
        assert_eq!(off, before);
    }

    fn survey_state() -> AppState {
        let mut st = AppState::new();
        st.update_peer_survey(crate::survey::classify(Ok(crate::survey::tests::reply())));
        st
    }

    /// With the survey on, the left panel holds the addresses and window,
    /// the eight largest families and `other` as bars, and the non-Core
    /// share; the right, the v2 and mismatch shares, the top AS, the last
    /// connection and the probe count.
    #[test]
    fn survey_panels() {
        let st = survey_state();
        let s = st.peer_survey.as_ref().unwrap();
        let left: Vec<String> = survey_left_lines(s, 38).iter().map(line_text).collect();
        assert_eq!(left[0], "  1,204 addrs, last 30 d");
        assert!(left[1].starts_with("  core           ") && left[1].ends_with(" 89.7%"), "{left:?}");
        assert!(left[9].starts_with("  other "), "{left:?}");
        assert_eq!(left.last().map(String::as_str), Some("  non-Core 5.5 %"));
        assert_eq!(left.len(), 11);
        for l in &left {
            assert!(l.chars().count() <= 38, "fits the panel: {l:?}");
        }

        let right: Vec<String> = survey_right_lines(s, 1_790_000_042).iter().map(line_text).collect();
        assert_eq!(right[0], "  v2:          41.0 % (494)");
        assert_eq!(right[1], "  mismatches:  0.4 % (5)");
        assert_eq!(right[3], "    AS64496    7.0 %");
        assert!(right.contains(&"  last survey: 42s ago, completed".to_string()), "{right:?}");
        assert!(right.contains(&"  connections: 1,300 ok, 2,100 failed".to_string()), "{right:?}");
        assert_eq!(right.last().map(String::as_str), Some("  probed:      600 addrs"));
        for l in &right {
            assert!(l.chars().count() <= 38, "fits an 80-column terminal's panel: {l:?}");
        }

        // Probes off: no probe line. No `-asmap`: no AS list.
        let mut quiet = s.clone();
        quiet.probes = false;
        quiet.top_as.clear();
        let right: Vec<String> = survey_right_lines(&quiet, 1_790_000_042).iter().map(line_text).collect();
        assert!(!right.iter().any(|l| l.contains("probed")), "{right:?}");
        assert!(right.contains(&"  top AS:      none (needs -asmap)".to_string()), "{right:?}");

        // A survey that has reached nobody yet.
        let empty = crate::survey::Survey::default();
        let left: Vec<String> = survey_left_lines(&empty, 38).iter().map(line_text).collect();
        assert_eq!(left, ["  0 addrs, last 30 d", "  no address reached yet"]);
    }

    /// Row four is drawn whole where it fits, collapses to the summary
    /// line where it does not, and is not drawn at all without survey
    /// data (the survey off, an older node, a refusal).
    #[test]
    fn survey_row_fits_collapses_or_hides() {
        let st = survey_state();
        assert_eq!(survey_row(&st, 20, 11), SurveyRow::Panels(13));
        assert_eq!(survey_row(&st, 13, 11), SurveyRow::Panels(13));
        assert_eq!(survey_row(&st, 12, 11), SurveyRow::Line);
        assert_eq!(survey_row(&st, 1, 11), SurveyRow::Line);
        assert_eq!(survey_row(&st, 0, 11), SurveyRow::Hidden, "no room at all");

        let mut off = survey_state();
        let mnf = crate::rpc::RpcError::Rpc { code: crate::rpc::JSONRPC_METHOD_NOT_FOUND, message: "no".into() };
        off.update_peer_survey(crate::survey::classify(Err(mnf)));
        assert_eq!(survey_row(&off, 20, 11), SurveyRow::Hidden);
        assert_eq!(survey_row(&AppState::new(), 20, 11), SurveyRow::Hidden);
    }

    /// The whole view against a test backend: the survey row below the
    /// three fixed rows on a tall terminal, the summary line above the
    /// footer on a short one, nothing with the survey off. Trivia and Peer
    /// clients stay in every case.
    #[test]
    fn chain_view_draws_the_survey_row() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let render = |st: &AppState, w: u16, h: u16| -> Vec<String> {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, st)).unwrap();
            let buf = term.backend().buffer().clone();
            (0..h).map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect()).collect()
        };
        let st = survey_state();

        let tall = render(&st, 100, 40);
        assert!(tall[25].contains("Network Survey") && tall[25].contains("Survey Detail"), "{tall:#?}");
        assert!(tall.iter().any(|l| l.contains("1,204 addrs, last 30 d")));
        assert!(tall.iter().any(|l| l.contains("Trivia")) && tall.iter().any(|l| l.contains("Peer Clients")));
        assert!(!tall.iter().any(|l| l.contains("survey: 1,204")));

        let short = render(&st, 80, 30);
        assert!(short[28].contains("survey: 1,204 addrs, non-Core 5.5 %, v2 41 %"), "{short:#?}");
        assert!(!short.iter().any(|l| l.contains("Network Survey")));
        assert!(short.iter().any(|l| l.contains("Trivia")));

        let none = render(&AppState::new(), 100, 40);
        assert!(!none.iter().any(|l| l.contains("Network Survey") || l.contains("survey: 1,204")));
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
