use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};

use crate::nap::{ppm, ppm_percent, sat_btc, Bucket, Half, Published, Report, ReportValue};
use crate::state::AppState;
use crate::ui::{format_hash, format_num, render_loading_panel};

/// Published rows shown before the table stops growing.
const PUBLISHED_ROWS: usize = 6;

pub fn draw(f: &mut Frame, state: &AppState) {
    let published_height = match &state.nap_publisher {
        Half::On(p) => p.len().clamp(1, PUBLISHED_ROWS) as u16 + 3,
        _ => 3,
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),                // title
            Constraint::Length(6),                // status
            Constraint::Min(6),                   // keys and values
            Constraint::Length(9),                // breakdown of the selected value
            Constraint::Length(published_height), // published
            Constraint::Length(1),                // footer
        ])
        .split(f.area());

    draw_title(f, chunks[0], state);
    draw_status(f, chunks[1], state);
    match &state.nap_report {
        Half::On(r) => {
            draw_keys(f, chunks[2], r, state.selected_nap_row);
            draw_breakdown(f, chunks[3], r, state.selected_nap_row);
        }
        Half::Off => {
            message_panel(f, chunks[2], " Report ", "The aggregator is off: set napaggregator=1 to collect attestations from peers.");
            message_panel(f, chunks[3], " Breakdown ", "");
        }
        Half::Unknown => {
            render_loading_panel(f, chunks[2], " Report ");
            render_loading_panel(f, chunks[3], " Breakdown ");
        }
    }
    match &state.nap_publisher {
        Half::On(p) => draw_published(f, chunks[4], p),
        Half::Off => message_panel(f, chunks[4], " Published ", "Publishing is off: set nap=1 to serve attestations."),
        Half::Unknown => render_loading_panel(f, chunks[4], " Published "),
    }
    draw_footer(f, chunks[5], state);
}

fn draw_title(f: &mut Frame, area: Rect, state: &AppState) {
    let mut spans = vec![
        Span::styled(" satd ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" {} ", state.chain_name), Style::default().fg(Color::White)),
        Span::styled(state.version_line(), Style::default().fg(Color::DarkGray)),
        Span::styled(" NAP ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" @ #{}", format_num(state.blocks as u64)), Style::default().fg(Color::DarkGray)),
    ];
    if let Some(line) = state.rpc_failure_line() {
        spans.push(Span::styled(line, Style::default().fg(Color::Red)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_status(f: &mut Frame, area: Rect, state: &AppState) {
    let publisher = match &state.nap_publisher {
        Half::On(p) => {
            let valid = p.iter().filter(|a| a.status == "valid").count();
            format!("on   {} published, {} valid", p.len(), valid)
        }
        Half::Off => "off".into(),
        Half::Unknown => "...".into(),
    };
    let mut lines = vec![info_line("Publisher:", &publisher)];
    match &state.nap_report {
        Half::On(r) => {
            lines.push(info_line("Aggregator:", &format!("on   report at #{} {}", format_num(r.height), format_hash(&r.hash))));
            lines.push(info_line(
                "Held:",
                &format!("{}   counting {}   invalid {}", format_num(r.attestations), format_num(r.counting), format_num(r.invalid)),
            ));
            lines.push(info_line("UTXO total:", &format!("{}   digest {}", sat_btc(r.utxo_total_sat), format_hash(&r.digest))));
        }
        Half::Off => lines.push(info_line("Aggregator:", "off")),
        Half::Unknown => lines.push(info_line("Aggregator:", "...")),
    }
    f.render_widget(Paragraph::new(lines).block(panel(" NAP ")), area);
}

/// Each key, then its values, heaviest first. Only value rows are selectable.
fn draw_keys(f: &mut Frame, area: Rect, r: &Report, selected: usize) {
    if r.keys.is_empty() {
        message_panel(f, area, " Report ", "No attestations count yet: the aggregator collects them from publishing peers.");
        return;
    }
    let header = Row::new(vec!["Key / value", "Share", "Weight", "Coverage", "Coins", "Withdrawn"])
        .style(Style::default().fg(Color::Cyan));
    let mut rows = Vec::new();
    let mut selected_row = None;
    let mut value_index = 0;
    for key in &r.keys {
        let withdrawn = if key.withdrawn.outpoints == 0 { "-".into() } else { sat_btc(key.withdrawn.weight_sat) };
        rows.push(
            Row::new(vec![
                Cell::from(key.key.clone()),
                Cell::from(""),
                Cell::from(sat_btc(key.sum.weight_sat)),
                Cell::from(ppm_percent(key.coverage_ppm)),
                Cell::from(format_num(key.sum.outpoints)),
                Cell::from(withdrawn),
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        );
        for v in &key.values {
            if value_index == selected {
                selected_row = Some(rows.len());
            }
            value_index += 1;
            rows.push(Row::new(vec![
                Cell::from(format!("  {}", shown_value(&v.value))),
                Cell::from(ppm_percent(v.share_ppm)),
                Cell::from(sat_btc(v.sum.weight_sat)),
                Cell::from(ppm_percent(v.coverage_ppm)),
                Cell::from(format_num(v.sum.outpoints)),
                Cell::from(""),
            ]));
        }
    }
    let widths = [
        Constraint::Min(24),
        Constraint::Length(8),
        Constraint::Length(22),
        Constraint::Length(9),
        Constraint::Length(8),
        Constraint::Length(22),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().fg(Color::Yellow))
        .block(panel(&format!(" Report ({} keys) ", r.keys.len())));
    let mut table_state = TableState::default().with_selected(selected_row);
    f.render_stateful_widget(table, area, &mut table_state);
}

/// An empty value is shown so it cannot be mistaken for a missing one.
fn shown_value(value: &str) -> &str {
    if value.is_empty() { "(empty)" } else { value }
}

/// The selected value's breakdowns, each bucket as its share of the value.
fn draw_breakdown(f: &mut Frame, area: Rect, r: &Report, selected: usize) {
    let Some(&(k, v)) = r.value_rows().get(selected) else {
        message_panel(f, area, " Breakdown ", "");
        return;
    };
    let key = &r.keys[k];
    let value: &ReportValue = &key.values[v];
    let concentration: Vec<String> = value
        .concentration
        .iter()
        .map(|(n, p)| format!("top {n} {}", ppm_percent(*p)))
        .collect();
    let block = panel(&format!(
        " {} = {}   {} ",
        key.key,
        shown_value(&value.value),
        concentration.join("   ")
    ));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 4); 4])
        .split(inner);
    let columns: [(&str, &[Bucket]); 4] = [
        ("Value (BTC)", &value.value_tiers),
        ("Anchor age (blocks)", &value.anchor_age),
        ("Coin age (blocks)", &value.coin_age),
        ("Script", &value.script_types),
    ];
    for (area, (title, buckets)) in cols.iter().zip(columns) {
        let mut lines = vec![Line::from(Span::styled(title, Style::default().fg(Color::Cyan)))];
        lines.extend(buckets.iter().map(|b| {
            let share = ppm(b.sum.weight_sat, value.sum.weight_sat);
            let style = if b.sum.outpoints == 0 { Style::default().fg(Color::DarkGray) } else { Style::default() };
            Line::from(vec![
                Span::styled(format!("{:<9}", b.label), Style::default().fg(Color::Gray)),
                Span::styled(format!("{:>8}", ppm_percent(share)), style),
                Span::styled(format!(" {:>5}", format_num(b.sum.outpoints)), Style::default().fg(Color::DarkGray)),
            ])
        }));
        f.render_widget(Paragraph::new(lines), *area);
    }
}

fn draw_published(f: &mut Frame, area: Rect, published: &[Published]) {
    if published.is_empty() {
        message_panel(f, area, " Published ", "Nothing published yet: submitnapattestation adds a signed attestation.");
        return;
    }
    let header = Row::new(vec!["Outpoint", "Key", "Value", "Anchor", "Amount", "Status"])
        .style(Style::default().fg(Color::Cyan));
    let rows: Vec<Row> = published
        .iter()
        .take(PUBLISHED_ROWS)
        .map(|a| {
            let status = if a.status == "valid" { Style::default().fg(Color::Green) } else { Style::default().fg(Color::Yellow) };
            Row::new(vec![
                Cell::from(format_hash(&a.outpoint)),
                Cell::from(a.key.clone()),
                Cell::from(shown_value(&a.value).to_string()),
                Cell::from(format!("#{}", format_num(a.anchor_height))),
                Cell::from(a.amount_sat.map(sat_btc).unwrap_or_else(|| "-".into())),
                Cell::from(Span::styled(a.status.clone(), status)),
            ])
        })
        .collect();
    let more = published.len().saturating_sub(PUBLISHED_ROWS);
    let title = if more > 0 {
        format!(" Published ({}, first {PUBLISHED_ROWS} shown) ", published.len())
    } else {
        format!(" Published ({}) ", published.len())
    };
    let widths = [
        Constraint::Length(18),
        Constraint::Min(16),
        Constraint::Min(10),
        Constraint::Length(10),
        Constraint::Length(22),
        Constraint::Min(8),
    ];
    f.render_widget(Table::new(rows, widths).header(header).block(panel(&title)), area);
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
        Span::styled(": view  ", Style::default().fg(Color::DarkGray)),
        Span::raw("\u{2191}\u{2193}"),
        Span::styled(": value", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(footer), area);
}

fn panel(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(title.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
}

fn message_panel(f: &mut Frame, area: Rect, title: &str, text: &str) {
    let line = Line::from(Span::styled(format!("  {text}"), Style::default().fg(Color::DarkGray)));
    f.render_widget(Paragraph::new(line).block(panel(title)), area);
}

fn info_line<'a>(label: &'a str, value: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {:<14}", label), Style::default().fg(Color::Gray)),
        Span::styled(value.to_string(), Style::default().fg(Color::White)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nap::{parse_published, parse_report, Poll};
    use crate::state::ViewMode;
    use serde_json::json;

    fn render(width: u16, height: u16, state: &AppState) -> Vec<String> {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, state)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
            .collect()
    }

    fn published(key: &str, value: &str) -> serde_json::Value {
        json!([{
            "outpoint": format!("{}:1", "cd".repeat(32)), "key": key, "value": value,
            "anchor_height": 327_535, "status": "valid", "amount": 0.0001,
        }])
    }

    fn state_with(report: serde_json::Value, publisher: serde_json::Value) -> AppState {
        let mut st = AppState::new();
        st.update_nap_report(Poll::On(parse_report(&report).unwrap()));
        st.update_nap_publisher(Poll::On(parse_published(&publisher).unwrap()));
        st
    }

    #[test]
    fn the_view_shows_weights_in_btc_and_shares_as_percentages() {
        let st = state_with(crate::nap::tests::sample_report(), published("g1.key", "v"));
        let screen = render(140, 45, &st).join("\n");
        // The key's participating weight and coverage, then each value's
        // share of it, heaviest first.
        assert!(screen.contains("fork.x"), "{screen}");
        assert!(screen.contains("3.00000000 BTC"), "{screen}");
        assert!(screen.contains("15.00%"), "{screen}");
        assert!(screen.find("  yes").unwrap() < screen.find("  no").unwrap(), "{screen}");
        assert!(screen.contains("66.66%") && screen.contains("33.33%"), "{screen}");
        // Withdrawals apart, in their own column.
        assert!(screen.contains("0.00050000 BTC"), "{screen}");
        // The first value is selected, and its breakdown is drawn.
        assert!(screen.contains("fork.x = yes"), "{screen}");
        assert!(screen.contains("top 10 100.00%"), "{screen}");
        assert!(screen.contains(">=262080"), "{screen}");
        assert!(screen.contains("p2tr"), "{screen}");
        // The tip it was computed at, and what the publisher serves.
        assert!(screen.contains("report at #900"), "{screen}");
        assert!(screen.contains("1 published, 1 valid"), "{screen}");
        assert!(screen.contains("g1.key"), "{screen}");
        assert!(screen.contains("0.00010000 BTC"), "{screen}");
    }

    #[test]
    fn moving_the_selection_draws_that_values_breakdown() {
        let mut st = state_with(crate::nap::tests::sample_report(), json!([]));
        st.move_nap_selection(1);
        assert!(render(140, 45, &st).join("\n").contains("fork.x = no"));
        // Past the last row it stays on the last row.
        st.move_nap_selection(5);
        assert_eq!(st.selected_nap_row, 1);
        st.move_nap_selection(-9);
        assert_eq!(st.selected_nap_row, 0);
    }

    #[test]
    fn holder_chosen_strings_cannot_put_control_characters_on_the_terminal() {
        let mut report = crate::nap::tests::sample_report();
        report["keys"][0]["key"] = json!("evil\u{1b}]0;owned\u{7}key");
        report["keys"][0]["values"][0]["value"] = json!("yes\u{1b}[2J\u{9b}31m");
        let st = state_with(report, published("pub\u{1b}[31mkey", "v\r\n"));
        let rows = render(140, 45, &st);
        let screen = rows.join("\n");
        // Each control character is drawn as `?`, so it is visible.
        assert!(screen.contains("evil?]0;owned?key"), "{screen}");
        assert!(screen.contains("yes?[2J?31m"), "{screen}");
        assert!(screen.contains("pub?[31mkey"), "{screen}");
        assert!(screen.contains("v??"), "{screen}");
        // And none reaches the buffer the terminal is drawn from.
        for row in &rows {
            assert!(!row.chars().any(|c| c.is_control()), "{row:?}");
        }
    }

    #[test]
    fn an_empty_report_and_a_disabled_half_say_so() {
        let mut st = AppState::new();
        st.update_nap_report(Poll::On(parse_report(&json!({
            "height": 1, "hash": "00", "utxo_total_sat": 0, "digest": "e3", "attestations": 0,
            "invalid": 0, "counting": 0, "keys": [],
        })).unwrap()));
        st.update_nap_publisher(Poll::Off);
        let screen = render(140, 45, &st).join("\n");
        assert!(screen.contains("No attestations count yet"), "{screen}");
        assert!(screen.contains("Publishing is off"), "{screen}");
    }

    #[test]
    fn key_five_is_offered_only_while_the_node_has_nap_on() {
        let mut st = AppState::new();
        // Not known yet, then both halves off: the key does nothing.
        st.press_nap_key();
        assert_ne!(st.active_mode(), ViewMode::Nap);
        st.update_nap_publisher(Poll::Off);
        st.update_nap_report(Poll::Off);
        st.press_nap_key();
        assert_ne!(st.active_mode(), ViewMode::Nap);
        // Either half on offers it.
        st.update_nap_publisher(Poll::On(vec![]));
        st.press_nap_key();
        assert_eq!(st.active_mode(), ViewMode::Nap);
        // A failure says nothing about NAP being off: the view stays.
        st.update_nap_publisher(Poll::Failed("timed out".into()));
        assert_eq!(st.active_mode(), ViewMode::Nap);
        assert!(st.rpc_failures.contains_key("listnapattestations"));
        // A node restarted with NAP off takes it away, and off is no failure.
        st.update_nap_publisher(Poll::Off);
        assert_ne!(st.active_mode(), ViewMode::Nap);
        assert!(st.rpc_failures.is_empty());
    }

    #[test]
    fn help_and_footers_list_key_five_only_while_nap_is_on() {
        let help = |st: &AppState| {
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 60)).unwrap();
            terminal.draw(|f| crate::ui::help::draw(f, st)).unwrap();
            let buffer = terminal.backend().buffer();
            (0..60u16)
                .map(|y| (0..120u16).map(|x| buffer[(x, y)].symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        };
        let mut st = AppState::new();
        st.update_nap_publisher(Poll::Off);
        st.update_nap_report(Poll::Off);
        assert!(!help(&st).contains("Force the NAP view"));
        assert_eq!(crate::ui::view_keys(&st), "1/2/3/4");
        st.update_nap_report(Poll::On(parse_report(&crate::nap::tests::sample_report()).unwrap()));
        assert!(help(&st).contains("Force the NAP view"));
        assert_eq!(crate::ui::view_keys(&st), "1/2/3/4/5");
        st.press_nap_key();
        assert!(help(&st).contains("NAP View"));
        assert!(render(140, 45, &st).join("\n").contains("1/2/3/4/5: view"));
    }

    #[test]
    fn the_view_renders_on_a_small_terminal_without_panicking() {
        let st = state_with(crate::nap::tests::sample_report(), published("k", "v"));
        for (width, height) in [(80, 24), (60, 20), (40, 12), (20, 8)] {
            assert_eq!(render(width, height, &st).len(), height as usize);
        }
    }
}
