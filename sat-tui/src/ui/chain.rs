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
    draw_extra_rows(f, chunks[4], state);
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
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} ", state.chain_name),
            Style::default().fg(Color::White),
        ),
        Span::styled(
            dot_glyph,
            Style::default().fg(dot_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{} ", health_label), Style::default().fg(dot_color)),
        Span::styled(state.version_line(), Style::default().fg(Color::DarkGray)),
        Span::styled(uptime_str, Style::default().fg(Color::DarkGray)),
        Span::styled(
            " chain & issuance ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
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
        info_line(
            "Halving In:",
            &format!("{} blk", format_num(to_halving as u64)),
        ),
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
        info_line("Δ Est:", &change_str),
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
            Span::styled(
                format!("  {:<24}", truncate(&crate::nap::printable(name), 24)),
                Style::default().fg(Color::White),
            ),
            Span::styled(format!("{:>3}", count), Style::default().fg(Color::Cyan)),
            Span::styled(format!("  {:>5.1}%", pct), Style::default().fg(Color::Gray)),
        ])
    };

    if let Some(map) = state.peer_behavior.as_ref().filter(|m| !m.is_empty()) {
        // Six inner lines: four families, `other`, and the mismatch count;
        // with alt-slot peers connected, three families and their line.
        let total = map.len();
        let (alt_matched, alt_fallback) = crate::behavior::alt_slot_counts(map);
        let alt = alt_matched + alt_fallback > 0;
        let mut lines: Vec<Line<'static>> =
            crate::behavior::family_distribution(map, if alt { 3 } else { 4 })
                .iter()
                .map(|(name, count)| row(name, *count, total))
                .collect();
        let mismatches = crate::behavior::mismatch_count(map);
        lines.push(Line::from(Span::styled(
            format!("  fingerprint mismatches: {mismatches}"),
            Style::default().fg(if mismatches > 0 {
                Color::Red
            } else {
                Color::DarkGray
            }),
        )));
        if alt {
            lines.push(Line::from(Span::styled(
                format!("  alt-slots: {alt_matched} matched, {alt_fallback} fallback"),
                Style::default().fg(Color::Gray),
            )));
        }
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
        dist.iter()
            .map(|(name, count)| row(name, *count, total))
            .collect()
    }
}

// ---- Network Survey and Network Crawl ---------------------------------------

/// How rows four (the survey) and five (the crawl) are drawn in the space
/// below row three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtraRow {
    /// No data: the row is not drawn.
    Hidden,
    /// Two panels, this many lines tall.
    Panels(u16),
    /// One summary line above the footer: the panels do not fit, or the
    /// crawl supersedes the survey.
    Line,
}

/// Whether the survey row is drawn: while the survey runs, and while the
/// crawl supersedes it where `-peersurvey` was asked for. A node with the
/// crawl on and the survey never asked for still says the survey is
/// superseded; it shows no survey row.
fn survey_shown(state: &AppState) -> bool {
    match &state.peer_survey {
        None => false,
        Some(s) if s.superseded => state
            .crawl
            .as_ref()
            .is_some_and(|c| c.peersurvey_superseded),
        Some(_) => true,
    }
}

/// The survey's and the crawl's rows for `space` lines below row three,
/// when the survey's panels need `survey_needed` inner lines and the
/// crawl's `crawl_needed`. Panels stack from the top of the space, the
/// survey's first; summary lines sit at its foot, the crawl's last. A
/// superseded survey is always its line. Where both rows are drawn the
/// crawl keeps at least its line.
pub fn extra_rows(
    state: &AppState,
    space: u16,
    survey_needed: usize,
    crawl_needed: usize,
) -> (ExtraRow, ExtraRow) {
    let crawl_shown = state.crawl.is_some();
    let mut left = space;
    let survey = if !survey_shown(state) || left == 0 {
        ExtraRow::Hidden
    } else if state.peer_survey.as_ref().is_some_and(|s| s.superseded) {
        ExtraRow::Line
    } else {
        let height = survey_needed as u16 + 2;
        if left >= height + u16::from(crawl_shown) {
            ExtraRow::Panels(height)
        } else {
            ExtraRow::Line
        }
    };
    let survey = match survey {
        // One line left: it goes to the crawl.
        ExtraRow::Line if crawl_shown && left == 1 => ExtraRow::Hidden,
        other => other,
    };
    left -= match survey {
        ExtraRow::Hidden => 0,
        ExtraRow::Panels(h) => h,
        ExtraRow::Line => 1,
    };
    let crawl = if !crawl_shown || left == 0 {
        ExtraRow::Hidden
    } else {
        let height = crawl_needed as u16 + 2;
        if left >= height {
            ExtraRow::Panels(height)
        } else {
            ExtraRow::Line
        }
    };
    (survey, crawl)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn draw_extra_rows(f: &mut Frame, area: Rect, state: &AppState) {
    if area.height == 0 {
        return;
    }
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let inner_width = cols[0].width.saturating_sub(2);
    let survey = state.peer_survey.as_ref().map(|s| {
        (
            s,
            survey_left_lines(s, inner_width),
            survey_right_lines(s, now_unix()),
        )
    });
    let crawl = state
        .crawl
        .as_ref()
        .map(|c| (c, crawl_left_lines(c, inner_width), crawl_right_lines(c)));
    let needed = |l: &[Line<'_>], r: &[Line<'_>]| l.len().max(r.len());
    let (survey_row, crawl_row) = extra_rows(
        state,
        area.height,
        survey.as_ref().map_or(0, |(_, l, r)| needed(l, r)),
        crawl.as_ref().map_or(0, |(_, l, r)| needed(l, r)),
    );

    let mut top = area.y;
    let mut foot = area.y + area.height;
    let mut line_at = |f: &mut Frame, text: String| {
        foot -= 1;
        let line = Line::from(Span::styled(
            format!(" {text}"),
            Style::default().fg(Color::Gray),
        ));
        f.render_widget(
            Paragraph::new(line),
            Rect {
                y: foot,
                height: 1,
                ..area
            },
        );
    };
    // Lines from the foot up: the crawl's lowest.
    if let (ExtraRow::Line, Some((c, _, _))) = (crawl_row, &crawl) {
        line_at(f, c.summary());
    }
    if let (ExtraRow::Line, Some((s, _, _))) = (survey_row, &survey) {
        line_at(
            f,
            if s.superseded {
                s.superseded_line()
            } else {
                s.summary()
            },
        );
    }
    let mut panels = |f: &mut Frame,
                      height: u16,
                      titles: (&str, &str),
                      left: &[Line<'_>],
                      right: &[Line<'_>]| {
        let left_area = Rect {
            y: top,
            height,
            ..cols[0]
        };
        let right_area = Rect {
            y: top,
            height,
            ..cols[1]
        };
        render_panel(f, left_area, titles.0, left);
        render_panel(f, right_area, titles.1, right);
        top += height;
    };
    if let (ExtraRow::Panels(h), Some((_, l, r))) = (survey_row, &survey) {
        panels(f, h, (" Network Survey ", " Survey Detail "), l, r);
    }
    if let (ExtraRow::Panels(h), Some((_, l, r))) = (crawl_row, &crawl) {
        panels(f, h, (" Network Crawl ", " Crawl Detail "), l, r);
    }
}

/// A bar per family, `pct` giving each count's share: two-cell indent,
/// label, count, bar, share; `width` cells inside the panel's border. The
/// count (observed and claimed records together) is right-aligned in a
/// column as wide as the largest. A bar's observed records are full
/// blocks, its claimed ones (the user agent's word alone) the dark shade
/// after them, in the family's colour; the share is of both.
fn family_bar_lines(
    bars: Vec<crate::survey::FamilyBar>,
    pct: impl Fn(u64) -> f64,
    width: u16,
) -> Vec<Line<'static>> {
    const LABEL: usize = 14;
    let count_width = bars
        .iter()
        .map(|b| format_num(b.total()).chars().count())
        .max()
        .unwrap_or(1);
    // Two-cell indent, label, space, count, space, bar, space, `100.0%`.
    let bar_width = (width as usize)
        .saturating_sub(2 + LABEL + 1 + count_width + 1 + 1 + 6)
        .clamp(4, 30);
    let cells = |n: u64| (pct(n) / 100.0 * bar_width as f64).round() as usize;
    bars.into_iter()
        .map(|bar| {
            let total = bar.total();
            let share = pct(total);
            // A family with any record shows at least one cell, and each
            // part with any record one of its own where there is room.
            let filled = cells(total).clamp(usize::from(total > 0), bar_width);
            let mut observed = cells(bar.observed).clamp(usize::from(bar.observed > 0), filled);
            let mut claimed = filled - observed;
            // Claimed records show a cell: a free one, or, on a full bar,
            // one of the observed part's while it keeps one of its own.
            if bar.claimed > 0 && claimed == 0 {
                if filled < bar_width {
                    claimed = 1;
                } else if observed > 1 {
                    observed -= 1;
                    claimed = 1;
                }
            }
            let empty = bar_width - observed - claimed;
            let color = match bar.name.as_str() {
                "core" => Color::Green,
                "unknown" | "other" => Color::DarkGray,
                _ => Color::Yellow,
            };
            Line::from(vec![
                Span::styled(
                    format!("  {:<width$} ", truncate(&bar.name, LABEL), width = LABEL),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("{:>count_width$} ", format_num(total)),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled("\u{2588}".repeat(observed), Style::default().fg(color)),
                Span::styled("\u{2593}".repeat(claimed), Style::default().fg(color)),
                Span::styled(
                    "\u{2591}".repeat(empty),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!(" {:>5.1}%", share),
                    Style::default().fg(Color::Gray),
                ),
            ])
        })
        .collect()
}

fn non_core_line(pct: f64) -> Line<'static> {
    Line::from(vec![
        Span::styled("  non-Core ", Style::default().fg(Color::Gray)),
        Span::styled(format!("{:.1} %", pct), Style::default().fg(Color::Cyan)),
    ])
}

/// The Network crawl panel, `width` cells inside its border: the state
/// (with every hold reason), the reachable count, a bar per family
/// (observed and claimed, as the survey's; the eight largest, then
/// `other`) and the non-Core share.
pub fn crawl_left_lines(c: &crate::crawl::Crawl, width: u16) -> Vec<Line<'static>> {
    use crate::crawl::CrawlState;
    let color = match c.state {
        CrawlState::Running => Color::Green,
        CrawlState::Held(_) => Color::Yellow,
        CrawlState::Stopped => Color::Red,
    };
    let state = truncate(&c.state_text(), (width as usize).saturating_sub(2));
    let mut lines = vec![
        Line::from(Span::styled(
            format!("  {state}"),
            Style::default().fg(color),
        )),
        Line::from(Span::styled(
            format!("  {} reachable", format_num(c.reachable)),
            Style::default().fg(Color::White),
        )),
    ];
    if c.reachable == 0 {
        lines.push(Line::from(Span::styled(
            "  no address reachable yet",
            Style::default().fg(Color::DarkGray),
        )));
        return lines;
    }
    lines.extend(family_bar_lines(c.family_bars(), |n| c.pct(n), width));
    lines.push(non_core_line(c.non_core_pct()));
    lines
}

/// The Crawl detail panel: the reachable addresses by network and by
/// transport (v2 and v1, v1 only, v1 with v2 never tried as it was not
/// advertised, v2 only, v2 not yet checked over v1), mismatches, the
/// claimed, fake and closed-early shares, sessions since start, sessions
/// open against the limits, and the book against its cap. The fake and
/// closed-early lines are drawn for a node that reports them, zero or not.
pub fn crawl_right_lines(c: &crate::crawl::Crawl) -> Vec<Line<'static>> {
    let row = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("  {:<14}", label), Style::default().fg(Color::Gray)),
            Span::styled(value, Style::default().fg(Color::White)),
        ])
    };
    let share = |n: u64| format!("{:.1} % ({})", c.pct(n), format_num(n));
    let mut lines: Vec<Line<'static>> = c
        .by_network
        .iter()
        .map(|(net, n)| row(&format!("{net}:"), share(*n)))
        .collect();
    let t = &c.transport;
    lines.push(row("v2 + v1:", share(t.v2_and_v1)));
    lines.push(row("v1 only:", share(t.v1_only)));
    lines.push(row("v1 no v2 ad:", share(t.v1_v2_untried)));
    lines.push(row("v2 only:", share(t.v2_only)));
    lines.push(row("v2 unchecked:", share(t.v2_unconfirmed)));
    lines.push(row("mismatches:", share(c.mismatches)));
    // The addresses no row matched whose user agent names a family: the
    // dark part of that family's bar, listed here too.
    let claimed = c.claimed_total();
    if claimed > 0 {
        lines.push(row("claimed:", share(claimed)));
        for (family, n) in c.claimed.iter().take(crate::survey::TOP_CLAIMED) {
            lines.push(row(&format!("  {family}"), share(*n)));
        }
    }
    if let Some(closed_early) = c.closed_early {
        lines.push(row("fake:", share(c.fake_total())));
        for (family, n) in c.fake.iter().take(crate::survey::TOP_FAKE) {
            lines.push(row(&format!("  {family}"), share(*n)));
        }
        lines.push(row("closed early:", share(closed_early)));
    }
    lines.push(row(
        "reached:",
        format!("{} sessions", format_num(c.reached)),
    ));
    lines.push(row(
        "unreached:",
        format!("{} sessions", format_num(c.unreached)),
    ));
    lines.push(row(
        "in flight:",
        format!(
            "{}/{}, tor {}/{}",
            c.in_flight_clearnet, c.concurrency, c.in_flight_tor, c.tor_concurrency
        ),
    ));
    lines.push(row(
        "book:",
        format!("{} / {}", format_num(c.book), format_num(c.book_max)),
    ));
    lines
}

/// The Network survey panel, `width` cells inside its border: the
/// addresses and the window, a bar per family (observed and claimed; the
/// eight largest, then `other`), and the non-Core share.
pub fn survey_left_lines(s: &crate::survey::Survey, width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        format!(
            "  {} addrs, last {} d",
            format_num(s.addresses),
            crate::survey::WINDOW_DAYS
        ),
        Style::default().fg(Color::White),
    ))];
    if s.addresses == 0 {
        lines.push(Line::from(Span::styled(
            "  no address reached yet",
            Style::default().fg(Color::DarkGray),
        )));
        return lines;
    }
    lines.extend(family_bar_lines(s.family_bars(), |n| s.pct(n), width));
    lines.push(non_core_line(s.non_core_pct()));
    lines
}

/// The Survey detail panel: v2 and mismatch shares, the claimed, fake
/// and closed-early shares, the five largest autonomous systems, the last
/// survey connection against `now` (Unix seconds), the connection counts
/// and, with probes on, how many addresses carry a probe outcome. The fake
/// and closed-early lines are drawn for a node that reports them, zero or
/// not.
pub fn survey_right_lines(s: &crate::survey::Survey, now: u64) -> Vec<Line<'static>> {
    let row = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("  {:<14}", label), Style::default().fg(Color::Gray)),
            Span::styled(value, Style::default().fg(Color::White)),
        ])
    };
    let share = |n: u64| format!("{:.1} % ({})", s.pct(n), format_num(n));
    let mut lines = vec![
        row("v2:", share(s.v2)),
        row("mismatches:", share(s.mismatches)),
    ];
    // The records no row matched whose user agent names a family: the
    // dark part of that family's bar, listed here too.
    let claimed: u64 = s.claimed.iter().map(|(_, n)| n).sum();
    if claimed > 0 {
        lines.push(row("claimed:", share(claimed)));
        for (family, n) in s.claimed.iter().take(crate::survey::TOP_CLAIMED) {
            lines.push(row(&format!("  {family}"), share(*n)));
        }
    }
    if let Some(closed_early) = s.closed_early {
        let fake = s.fake_total();
        lines.push(row("fake:", share(fake)));
        for (family, n) in s.fake.iter().take(crate::survey::TOP_FAKE) {
            lines.push(row(&format!("  {family}"), share(*n)));
        }
        lines.push(row("closed early:", share(closed_early)));
    }
    if s.top_as.is_empty() {
        let why = if s.addresses == 0 {
            "none"
        } else {
            "none (needs -asmap)"
        };
        lines.push(row("top AS:", why.into()));
    } else {
        lines.push(row("top AS:", String::new()));
        for (asn, count) in s.top_as.iter().take(crate::survey::TOP_AS) {
            lines.push(row(
                &format!("  AS{asn}"),
                format!("{:.1} %", s.pct(*count)),
            ));
        }
    }
    lines.push(row("last survey:", s.last_line(now)));
    lines.push(row(
        "connections:",
        format!(
            "{} ok, {} failed",
            format_num(s.completed),
            format_num(s.failed)
        ),
    ));
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
        info_line(
            "Next halving block:",
            &format_num(next_halving_block as u64),
        ),
        info_line(
            "Next retarget block:",
            &format_num(next_retarget_block as u64),
        ),
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
    let bar = format!("{}{}", "\u{2588}".repeat(filled), "\u{2591}".repeat(empty),);
    Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(bar, Style::default().fg(color)),
        Span::styled(
            format!("  {:.1}%", frac * 100.0),
            Style::default().fg(Color::DarkGray),
        ),
    ])
}

fn render_panel(f: &mut Frame, area: Rect, title: &str, lines: &[Line<'_>]) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title.to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
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
        Span::styled(
            crate::ui::view_keys(state),
            Style::default().fg(Color::White),
        ),
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
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        _ => "Dec",
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
        assert!(
            s.starts_with("Apr 2026") || s.starts_with("May 2026"),
            "got {}",
            s
        );
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

        st.update_peer_behavior(crate::behavior::classify(Ok(
            crate::behavior::tests::reply(),
        )));
        let after: Vec<String> = peer_client_lines(&st).iter().map(line_text).collect();
        assert!(
            after
                .iter()
                .any(|l| l.contains("btcd [core]") && l.contains("1")),
            "{after:?}"
        );
        assert!(
            after.iter().any(|l| l.contains("bitcoin-seeder")),
            "{after:?}"
        );
        assert!(!after.iter().any(|l| l.contains("/Satoshi:")), "{after:?}");
        assert_eq!(
            after.last().map(String::as_str),
            Some("  fingerprint mismatches: 1")
        );
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
        // Core's 1,080 observed and 41 claimed: 93.1 %, the claimed part
        // in the dark shade.
        assert!(
            left[1].starts_with("  core           ") && left[1].ends_with(" 93.1%"),
            "{left:?}"
        );
        assert!(left[1].contains('\u{2593}'), "the claimed part: {left:?}");
        assert!(left[1].starts_with("  core           1,121 "), "{left:?}");
        assert!(
            left[2].starts_with("  btcd ") && left[2].contains('\u{2593}'),
            "{left:?}"
        );
        assert!(
            left.iter()
                .any(|l| l.starts_with("  unknown ") && l.ends_with("  0.4%")),
            "only the truly unknown: {left:?}"
        );
        assert!(left[9].starts_with("  other "), "{left:?}");
        assert_eq!(left.last().map(String::as_str), Some("  non-Core 5.5 %"));
        assert_eq!(left.len(), 11);
        for l in &left {
            assert!(l.chars().count() <= 38, "fits the panel: {l:?}");
        }

        let right: Vec<String> = survey_right_lines(s, 1_790_000_042)
            .iter()
            .map(line_text)
            .collect();
        assert_eq!(right[0], "  v2:           41.0 % (494)");
        assert_eq!(right[1], "  mismatches:   0.4 % (5)");
        assert_eq!(right[2], "  claimed:      3.6 % (43)");
        assert_eq!(right[3], "    core        3.4 % (41)");
        assert_eq!(right[4], "    btcd        0.2 % (2)");
        assert_eq!(right[5], "  fake:         0.3 % (4)");
        assert_eq!(right[6], "    core        0.3 % (4)");
        assert_eq!(right[7], "  closed early: 0.5 % (6)");
        assert_eq!(right[9], "    AS64496     7.0 %");
        assert!(
            right.contains(&"  last survey:  42s ago, completed".to_string()),
            "{right:?}"
        );
        assert!(
            right.contains(&"  connections:  1,300 ok, 2,100 failed".to_string()),
            "{right:?}"
        );
        assert_eq!(
            right.last().map(String::as_str),
            Some("  probed:       600 addrs")
        );
        for l in &right {
            assert!(
                l.chars().count() <= 38,
                "fits an 80-column terminal's panel: {l:?}"
            );
        }

        // Nothing claimed (or an older node): no claimed lines.
        let mut unclaimed = s.clone();
        unclaimed.claimed.clear();
        let right: Vec<String> = survey_right_lines(&unclaimed, 1_790_000_042)
            .iter()
            .map(line_text)
            .collect();
        assert!(!right.iter().any(|l| l.contains("claimed")), "{right:?}");

        // A node that reports no fake or closed-early counts: no such
        // lines. One that reports them at zero: both, at zero.
        let older = crate::survey::Survey {
            closed_early: None,
            fake: Vec::new(),
            ..s.clone()
        };
        let right: Vec<String> = survey_right_lines(&older, 1_790_000_042)
            .iter()
            .map(line_text)
            .collect();
        assert!(
            !right
                .iter()
                .any(|l| l.contains("fake") || l.contains("closed early")),
            "{right:?}"
        );
        let none = crate::survey::Survey {
            closed_early: Some(0),
            fake: Vec::new(),
            ..s.clone()
        };
        let right: Vec<String> = survey_right_lines(&none, 1_790_000_042)
            .iter()
            .map(line_text)
            .collect();
        assert!(
            right.contains(&"  fake:         0.0 % (0)".to_string()),
            "{right:?}"
        );
        assert!(
            right.contains(&"  closed early: 0.0 % (0)".to_string()),
            "{right:?}"
        );

        // Probes off: no probe line. No `-asmap`: no AS list.
        let mut quiet = s.clone();
        quiet.probes = false;
        quiet.top_as.clear();
        let right: Vec<String> = survey_right_lines(&quiet, 1_790_000_042)
            .iter()
            .map(line_text)
            .collect();
        assert!(!right.iter().any(|l| l.contains("probed")), "{right:?}");
        assert!(
            right.contains(&"  top AS:       none (needs -asmap)".to_string()),
            "{right:?}"
        );

        // A survey that has reached nobody yet.
        let empty = crate::survey::Survey::default();
        let left: Vec<String> = survey_left_lines(&empty, 38)
            .iter()
            .map(line_text)
            .collect();
        assert_eq!(left, ["  0 addrs, last 30 d", "  no address reached yet"]);
    }

    /// Row four is drawn whole where it fits, collapses to the summary
    /// line where it does not, and is not drawn at all without survey
    /// data (the survey off, an older node, a refusal).
    #[test]
    fn survey_row_fits_collapses_or_hides() {
        let st = survey_state();
        let survey_row = |st: &AppState, space| extra_rows(st, space, 11, 12).0;
        assert_eq!(survey_row(&st, 20), ExtraRow::Panels(13));
        assert_eq!(survey_row(&st, 13), ExtraRow::Panels(13));
        assert_eq!(survey_row(&st, 12), ExtraRow::Line);
        assert_eq!(survey_row(&st, 1), ExtraRow::Line);
        assert_eq!(survey_row(&st, 0), ExtraRow::Hidden, "no room at all");
        assert_eq!(
            extra_rows(&st, 20, 11, 12).1,
            ExtraRow::Hidden,
            "no crawl row with the crawl off"
        );

        let mut off = survey_state();
        let mnf = crate::rpc::RpcError::Rpc {
            code: crate::rpc::JSONRPC_METHOD_NOT_FOUND,
            message: "no".into(),
        };
        off.update_peer_survey(crate::survey::classify(Err(mnf)));
        assert_eq!(survey_row(&off, 20), ExtraRow::Hidden);
        assert_eq!(survey_row(&AppState::new(), 20), ExtraRow::Hidden);
    }

    /// A node running the crawl, with `-peersurvey` asked for too
    /// (`superseded`) or not: getpeersurvey then says the survey is
    /// superseded either way.
    fn crawl_state(survey_asked: bool) -> AppState {
        let mut st = AppState::new();
        let mut crawl = crate::crawl::tests::reply();
        crawl["peersurvey_superseded"] = serde_json::json!(survey_asked);
        st.update_crawl(crate::crawl::classify(Ok(crawl)));
        let mut survey = crate::survey::tests::reply();
        survey["enabled"] = serde_json::json!(false);
        survey["superseded_by_crawl"] = serde_json::json!(true);
        if !survey_asked {
            survey = serde_json::json!({"addresses": 0, "families": {}, "mismatches": 0, "v2": {"count": 0, "share": 0.0},
                                        "top_as": [], "probed": 0, "enabled": false, "superseded_by_crawl": true});
        }
        st.update_peer_survey(crate::survey::classify(Ok(survey)));
        st
    }

    /// With the crawl on, the left panel holds the state, the reachable
    /// count, the families and the non-Core share; the right, the counts by
    /// network and transport, mismatches, sessions, sessions open against
    /// the limits and the book. Each line fits an 80-column terminal's
    /// panel.
    #[test]
    fn crawl_panels() {
        let st = crawl_state(true);
        let c = st.crawl.as_ref().unwrap();
        let left: Vec<String> = crawl_left_lines(c, 38).iter().map(line_text).collect();
        assert_eq!(left[0], "  running");
        assert_eq!(left[1], "  21,000 reachable");
        // Core's 20,000 observed and 350 claimed: 96.9 %, the claimed part
        // in the dark shade.
        assert!(
            left[2].starts_with("  core           ") && left[2].ends_with(" 96.9%"),
            "{left:?}"
        );
        assert!(left[2].contains('\u{2593}'), "the claimed part: {left:?}");
        assert!(
            left[3].starts_with("  btcd ") && left[3].contains('\u{2593}'),
            "{left:?}"
        );
        assert!(
            left.iter()
                .any(|l| l.starts_with("  unknown ") && l.ends_with("  0.5%")),
            "only the truly unknown: {left:?}"
        );
        assert!(left[10].starts_with("  other "), "{left:?}");
        assert_eq!(left.last().map(String::as_str), Some("  non-Core 1.4 %"));
        assert_eq!(left.len(), 12);
        // Each family's count next to its name, observed and claimed
        // together, right-aligned to the widest: core 20,000 + 350, btcd
        // 150 + 10, rbitcoin 40.
        assert!(left[2].starts_with("  core           20,350 "), "{left:?}");
        assert!(left[3].starts_with("  btcd              160 "), "{left:?}");
        assert!(
            left.iter()
                .any(|l| l.starts_with("  rbitcoin           40 ")),
            "{left:?}"
        );
        for l in &left {
            assert!(l.chars().count() <= 38, "fits the panel: {l:?}");
        }

        let right: Vec<String> = crawl_right_lines(c).iter().map(line_text).collect();
        assert_eq!(
            right,
            [
                "  ipv4:         59.5 % (12,500)",
                "  ipv6:         12.4 % (2,600)",
                "  onion:        28.1 % (5,900)",
                "  v2 + v1:      42.9 % (9,000)",
                "  v1 only:      7.1 % (1,500)",
                "  v1 no v2 ad:  47.6 % (10,000)",
                "  v2 only:      0.2 % (40)",
                "  v2 unchecked: 2.2 % (460)",
                "  mismatches:   0.1 % (12)",
                "  claimed:      1.7 % (360)",
                "    core        1.7 % (350)",
                "    btcd        0.0 % (10)",
                "  fake:         0.7 % (140)",
                "    core        0.7 % (140)",
                "  closed early: 0.5 % (100)",
                "  reached:      50,213 sessions",
                "  unreached:    140,022 sessions",
                "  in flight:    31/32, tor 8/8",
                "  book:         61,234 / 250,000",
            ]
        );
        for l in left.iter().chain(&right) {
            assert!(l.chars().count() <= 38, "fits the panel: {l:?}");
        }

        // A node that reports no fake or closed-early counts: no such
        // lines. One that reports them at zero: both, at zero. No claimed
        // address: no claimed line.
        let older = crate::crawl::Crawl {
            closed_early: None,
            fake: Vec::new(),
            ..c.clone()
        };
        let right: Vec<String> = crawl_right_lines(&older).iter().map(line_text).collect();
        assert!(
            !right
                .iter()
                .any(|l| l.contains("fake") || l.contains("closed early")),
            "{right:?}"
        );
        let none = crate::crawl::Crawl {
            closed_early: Some(0),
            fake: Vec::new(),
            claimed: Vec::new(),
            ..c.clone()
        };
        let right: Vec<String> = crawl_right_lines(&none).iter().map(line_text).collect();
        assert!(
            right.contains(&"  fake:         0.0 % (0)".to_string()),
            "{right:?}"
        );
        assert!(
            right.contains(&"  closed early: 0.0 % (0)".to_string()),
            "{right:?}"
        );
        assert!(!right.iter().any(|l| l.contains("claimed")), "{right:?}");

        // Held, with every reason; a long state is cut to the panel.
        let mut held = c.clone();
        held.state = crate::crawl::CrawlState::Held(vec![
            "initial_block_download".into(),
            "connect".into(),
            "network_inactive".into(),
        ]);
        let left: Vec<String> = crawl_left_lines(&held, 38).iter().map(line_text).collect();
        assert!(
            left[0].starts_with("  held: initial block download, -c"),
            "{left:?}"
        );
        assert!(left[0].chars().count() <= 38);
        held.state = crate::crawl::CrawlState::Stopped;
        assert_eq!(
            line_text(&crawl_left_lines(&held, 38)[0]),
            "  stopped (a crawl task panicked)"
        );

        // A crawl that has reached nobody yet.
        let empty = crate::crawl::Crawl::default();
        let left: Vec<String> = crawl_left_lines(&empty, 38).iter().map(line_text).collect();
        assert_eq!(
            left,
            ["  running", "  0 reachable", "  no address reachable yet"]
        );
    }

    /// The crawl row is drawn whole where it fits and collapses to its line
    /// where it does not. With the crawl on, the survey row is its
    /// superseded line where `-peersurvey` was asked for, and not drawn
    /// where it was not.
    #[test]
    fn crawl_row_fits_collapses_or_hides() {
        let st = crawl_state(true);
        assert_eq!(
            extra_rows(&st, 30, 11, 12),
            (ExtraRow::Line, ExtraRow::Panels(14))
        );
        assert_eq!(
            extra_rows(&st, 15, 11, 12),
            (ExtraRow::Line, ExtraRow::Panels(14))
        );
        assert_eq!(
            extra_rows(&st, 14, 11, 12),
            (ExtraRow::Line, ExtraRow::Line)
        );
        assert_eq!(extra_rows(&st, 2, 11, 12), (ExtraRow::Line, ExtraRow::Line));
        assert_eq!(
            extra_rows(&st, 1, 11, 12),
            (ExtraRow::Hidden, ExtraRow::Line),
            "the last line is the crawl's"
        );
        assert_eq!(
            extra_rows(&st, 0, 11, 12),
            (ExtraRow::Hidden, ExtraRow::Hidden)
        );

        let st = crawl_state(false);
        assert_eq!(
            extra_rows(&st, 30, 11, 12),
            (ExtraRow::Hidden, ExtraRow::Panels(14)),
            "no survey asked for"
        );

        // An older node: no getcrawlinfo, the survey row as before.
        let mut old = survey_state();
        let mnf = crate::rpc::RpcError::Rpc {
            code: crate::rpc::JSONRPC_METHOD_NOT_FOUND,
            message: "no".into(),
        };
        old.update_crawl(crate::crawl::classify(Err(mnf)));
        assert_eq!(
            extra_rows(&old, 30, 11, 12),
            (ExtraRow::Panels(13), ExtraRow::Hidden)
        );
        assert!(old.rpc_failures.is_empty());
    }

    fn render(st: &AppState, w: u16, h: u16) -> Vec<String> {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, st)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect())
            .collect()
    }

    /// The whole view against a test backend: the survey row below the
    /// three fixed rows on a tall terminal, the summary line above the
    /// footer on a short one, nothing with the survey off. Trivia and Peer
    /// clients stay in every case.
    #[test]
    fn chain_view_draws_the_survey_row() {
        let st = survey_state();

        let tall = render(&st, 100, 44);
        assert!(
            tall[25].contains("Network Survey") && tall[25].contains("Survey Detail"),
            "{tall:#?}"
        );
        assert!(tall.iter().any(|l| l.contains("1,204 addrs, last 30 d")));
        assert!(
            tall.iter().any(|l| l.contains("Trivia"))
                && tall.iter().any(|l| l.contains("Peer Clients"))
        );
        assert!(!tall.iter().any(|l| l.contains("survey: 1,204")));
        assert!(
            !tall
                .iter()
                .any(|l| l.contains("Network Crawl") || l.contains("crawl:"))
        );

        let short = render(&st, 80, 30);
        assert!(
            short[28].contains("survey: 1,204 addrs, non-Core 5.5 %, v2 41 %"),
            "{short:#?}"
        );
        assert!(!short.iter().any(|l| l.contains("Network Survey")));
        assert!(short.iter().any(|l| l.contains("Trivia")));

        let none = render(&AppState::new(), 100, 40);
        assert!(
            !none
                .iter()
                .any(|l| l.contains("Network Survey") || l.contains("survey: 1,204"))
        );
    }

    /// With the crawl on: its panels below the fixed rows and the survey's
    /// superseded line above the footer on a tall terminal; both as lines on
    /// a short one, the crawl's last.
    #[test]
    fn chain_view_draws_the_crawl_row() {
        let st = crawl_state(true);
        let tall = render(&st, 100, 51);
        assert!(
            tall[25].contains("Network Crawl") && tall[25].contains("Crawl Detail"),
            "{tall:#?}"
        );
        assert!(tall.iter().any(|l| l.contains("21,000 reachable")));
        assert!(tall.iter().any(|l| l.contains("v2 only:      0.2 % (40)")));
        assert!(
            tall[49].contains("survey: superseded by the crawl, 1,204 addrs kept"),
            "{tall:#?}"
        );
        assert!(
            tall.iter().any(|l| l.contains("closed early: 0.5 % (100)")),
            "{tall:#?}"
        );
        assert!(!tall.iter().any(|l| l.contains("Network Survey")));
        assert!(
            tall.iter().any(|l| l.contains("Trivia"))
                && tall.iter().any(|l| l.contains("Peer Clients"))
        );

        let short = render(&st, 80, 30);
        assert!(
            short[27].contains("survey: superseded by the crawl"),
            "{short:#?}"
        );
        assert!(
            short[28].contains("crawl: running, 21,000 reachable, non-Core 1.4 %, v2-only 40"),
            "{short:#?}"
        );
        assert!(!short.iter().any(|l| l.contains("Network Crawl")));

        let alone = render(&crawl_state(false), 100, 51);
        assert!(alone.iter().any(|l| l.contains("Network Crawl")));
        assert!(!alone.iter().any(|l| l.contains("survey")), "{alone:#?}");
    }

    /// No address can reach the screen from the crawl row: a reply that
    /// carries addresses in every place a name is read, and in keys the
    /// TUI does not read, draws none of them, tall or short.
    #[test]
    fn no_address_reaches_the_crawl_row() {
        const ADDRS: [&str; 5] = [
            "203.0.113.7",
            "2001:db8::1",
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx",
            "b32.i2p",
            ":8333",
        ];
        let mut v = crate::crawl::tests::reply();
        v["state"] = serde_json::json!("held");
        v["held_by"] = serde_json::json!(["203.0.113.7:8333", "[2001:db8::1]:8333"]);
        v["families"]["203.0.113.7:8333"] = serde_json::json!({"count": 9000, "share": 0.4});
        v["families"]["[2001:db8::1]:8333"] = serde_json::json!({"count": 8000, "share": 0.4});
        v["families"]["abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"] =
            serde_json::json!({"count": 7000, "share": 0.3});
        v["families"]["abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstu.b32.i2p"] =
            serde_json::json!({"count": 6000, "share": 0.3});
        for key in ["claimed", "fake"] {
            v[key]["203.0.113.7:8333"] = serde_json::json!({"count": 900, "share": 0.04});
            v[key]["[2001:db8::1]:8333"] = serde_json::json!({"count": 800, "share": 0.04});
        }
        v["stopped_by"] = serde_json::json!("203.0.113.7:8333");
        v["peers"] =
            serde_json::json!([{"addr": "203.0.113.7:8333"}, {"addr": "[2001:db8::1]:8333"}]);
        v["limits"]["networks"] = serde_json::json!(["203.0.113.7"]);
        let mut st = AppState::new();
        st.update_crawl(crate::crawl::classify(Ok(v)));
        assert!(st.crawl.is_some());
        for (w, h) in [(100, 50), (80, 30), (200, 60)] {
            let screen = render(&st, w, h).join("\n");
            assert!(screen.contains("held: ?, ?"), "{screen}");
            for a in ADDRS {
                assert!(!screen.contains(a), "{a} on a {w}x{h} screen:\n{screen}");
            }
        }
    }

    /// With alt-slot peers connected, Peer clients adds their line and
    /// still fits its six lines.
    #[test]
    fn peer_clients_alt_slot_line() {
        let mut st = AppState::new();
        let mut v = crate::behavior::tests::reply();
        v[0]["alt_slot"] = serde_json::json!({"rule": "family:non-core", "trust": "unverified", "fallback": false});
        st.update_peer_behavior(crate::behavior::classify(Ok(v)));
        let lines: Vec<String> = peer_client_lines(&st).iter().map(line_text).collect();
        assert_eq!(
            lines.last().map(String::as_str),
            Some("  alt-slots: 1 matched, 0 fallback")
        );
        assert!(lines.len() <= 6, "{lines:?}");
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
