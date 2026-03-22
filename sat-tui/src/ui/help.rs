use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::state::{AppState, ViewMode};

pub fn draw(f: &mut Frame, state: &AppState) {
    let size = f.area();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Help ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(size);

    let inner = block.inner(chunks[0]);
    f.render_widget(block, chunks[0]);

    let lines = match state.active_mode() {
        ViewMode::Ibd => ibd_help(),
        ViewMode::Steady => steady_help(),
    };

    let help = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(help, inner);

    let footer = Line::from(vec![
        Span::styled("h", Style::default().fg(Color::White)),
        Span::styled("/", Style::default().fg(Color::DarkGray)),
        Span::styled("q", Style::default().fg(Color::White)),
        Span::styled("/", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::White)),
        Span::styled(": close help", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(footer), chunks[1]);
}

fn heading(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_string(),
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    ))
}

fn label(key: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {:<14}", key), Style::default().fg(Color::Cyan)),
        Span::styled(desc.to_string(), Style::default().fg(Color::White)),
    ])
}

fn blank() -> Line<'static> {
    Line::from("")
}

fn ibd_help() -> Vec<Line<'static>> {
    vec![
        heading("IBD View  --  Initial Block Download"),
        blank(),
        heading("Progress Bar"),
        label("Blocks / Target", "Connected blocks vs network chain tip (from peers)."),
        label("blk/s", "Rate at which blocks are connected to the chain (EMA smoothed)."),
        label("hdr/s", "Rate at which block headers are being received from peers."),
        label("ETA", "Estimated time to sync, based on current blk/s rate."),
        blank(),
        heading("Block Map"),
        Line::from(vec![
            Span::styled("  Visualizes the state of every block in the download range.", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Each character represents a group of blocks. Colors:", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  \u{2588}", Style::default().fg(Color::Green)),
            Span::styled(" Connected   ", Style::default().fg(Color::White)),
            Span::styled("\u{2591}", Style::default().fg(Color::Cyan)),
            Span::styled(" Downloaded   ", Style::default().fg(Color::White)),
            Span::styled("\u{2593}", Style::default().fg(Color::Yellow)),
            Span::styled(" In-flight   ", Style::default().fg(Color::White)),
            Span::styled("\u{00B7}", Style::default().fg(Color::DarkGray)),
            Span::styled(" Pending", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Connected = validated and added to chain. Downloaded = stored on disk,", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("  awaiting sequential connection. In-flight = requested from a peer,", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("  awaiting response. Pending = queued for download.", Style::default().fg(Color::Gray)),
        ]),
        blank(),
        heading("Sync Rate Sparklines"),
        label("Top (yellow)", "Blocks connected per second over the last ~90 seconds."),
        label("Bottom (cyan)", "Blocks downloaded per second (across all peers)."),
        blank(),
        heading("Stats Panel"),
        label("Headers", "Total block headers received (chain structure, no block data)."),
        label("Connected", "Blocks fully validated and added to the chain tip."),
        label("Stored", "Blocks downloaded and stored but not yet connected."),
        label("In-Flight", "Block requests sent to peers, awaiting response."),
        label("Remaining", "Blocks still queued for download."),
        blank(),
        heading("Peer Table"),
        label("Recv", "Total blocks received from this peer during IBD."),
        label("Assigned", "Blocks currently assigned to this peer for download."),
        label("Rate", "Per-peer download rate in blocks/second."),
        blank(),
        heading("Keyboard"),
        label("q", "Quit (or close help)"),
        label("h / ?", "Toggle this help screen"),
        label("1 / 2", "Force IBD / Steady view (press again for auto)"),
        label("Up / Down", "Scroll the peer table"),
    ]
}

fn steady_help() -> Vec<Line<'static>> {
    vec![
        heading("Steady-State View  --  Synced Node Dashboard"),
        blank(),
        heading("Chain Panel"),
        label("Height", "Current block height (chain tip)."),
        label("Difficulty", "Current mining difficulty target."),
        label("Hash Rate", "Estimated network hash rate (from getmininginfo)."),
        label("Last Block", "Time since the most recent block was mined."),
        blank(),
        heading("Latest Block Panel"),
        label("Txs", "Number of transactions in the tip block."),
        label("Size / Weight", "Block size in bytes and weight units."),
        label("Fees", "Total transaction fees collected in the block."),
        label("Avg Rate", "Average fee rate across all transactions (sat/vB)."),
        blank(),
        heading("Mempool Panel"),
        label("Txs", "Unconfirmed transactions waiting for inclusion."),
        label("Size", "Total size of mempool transactions."),
        label("Min Rate", "Minimum fee rate to enter the mempool."),
        label("Tx Rate", "Transactions entering the mempool per second."),
        label("Distribution", "Sparkline showing transaction count by vByte size bucket."),
        blank(),
        heading("Fee Estimates Panel"),
        Line::from(vec![
            Span::styled("  Estimated fee rates (sat/vB) for confirmation within N blocks.", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Bar length is proportional to fee. Color: ", Style::default().fg(Color::Gray)),
            Span::styled("red", Style::default().fg(Color::Red)),
            Span::styled("=urgent, ", Style::default().fg(Color::Gray)),
            Span::styled("green", Style::default().fg(Color::Green)),
            Span::styled("=economy.", Style::default().fg(Color::Gray)),
        ]),
        blank(),
        heading("UTXO Set Panel"),
        label("UTXOs", "Total unspent transaction outputs in the chain."),
        label("Total", "Sum of all UTXO values in BTC."),
        label("Supply", "Percentage of 21M BTC cap currently in UTXOs."),
        label("Age Dist", "Sparkline: UTXO count by age (<1h to 3y+)."),
        blank(),
        heading("Network Panel"),
        label("Peers", "Connected peers (inbound accepting / outbound initiated)."),
        label("Recv / Sent", "Total bytes transferred with all peers."),
        blank(),
        heading("Keyboard"),
        label("q", "Quit (or close help)"),
        label("h / ?", "Toggle this help screen"),
        label("1 / 2", "Force IBD / Steady view (press again for auto)"),
        label("Up / Down", "Scroll the peer table"),
    ]
}
