mod rpc;
mod state;
mod ui;

use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::time::{interval, Duration};

use rpc::RpcClient;
use state::{AppState, ViewMode};

#[derive(Parser, Debug)]
#[command(name = "sat-tui", version, about = "Terminal dashboard for satd")]
struct CliArgs {
    #[arg(long, help = "Use regtest network")]
    regtest: bool,

    #[arg(long, help = "Use testnet network")]
    testnet: bool,

    #[arg(long, help = "Use signet network")]
    signet: bool,

    #[arg(long, default_value = "127.0.0.1", help = "RPC host")]
    rpcconnect: String,

    #[arg(long, help = "RPC port")]
    rpcport: Option<u16>,

    #[arg(long, help = "RPC username")]
    rpcuser: Option<String>,

    #[arg(long, help = "RPC password")]
    rpcpassword: Option<String>,

    #[arg(long, help = "Path to cookie file")]
    rpccookiefile: Option<PathBuf>,

    #[arg(long, help = "Data directory")]
    datadir: Option<PathBuf>,
}

/// Convert single-dash flags to double-dash for clap compatibility.
fn normalize_args(args: Vec<String>) -> Vec<String> {
    let known_flags = [
        "regtest", "testnet", "signet", "rpcconnect", "rpcport",
        "rpcuser", "rpcpassword", "rpccookiefile", "datadir",
    ];
    args.into_iter()
        .map(|arg| {
            if !arg.starts_with('-') || arg.starts_with("--") {
                return arg;
            }
            let rest = &arg[1..];
            let flag_name = rest.split('=').next().unwrap_or(rest);
            if known_flags.contains(&flag_name) {
                format!("-{}", arg)
            } else {
                arg
            }
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_args: Vec<String> = std::env::args().collect();
    let normalized = normalize_args(raw_args);
    let cli = CliArgs::parse_from(normalized);

    let rpcport = cli.rpcport.unwrap_or(if cli.regtest {
        18443
    } else if cli.testnet {
        18332
    } else if cli.signet {
        38332
    } else {
        8332
    });

    // Resolve auth — use cookie path for automatic re-auth on satd restart
    let rpc_client = if let (Some(u), Some(p)) = (&cli.rpcuser, &cli.rpcpassword) {
        Arc::new(RpcClient::new(&cli.rpcconnect, rpcport, u, p))
    } else {
        let cookie_path = cli.rpccookiefile.unwrap_or_else(|| {
            let base = cli.datadir.clone().unwrap_or_else(rpc::default_datadir);
            let net_subdir = if cli.regtest {
                "regtest"
            } else if cli.testnet {
                "testnet3"
            } else if cli.signet {
                "signet"
            } else {
                ""
            };
            if net_subdir.is_empty() {
                base.join(".cookie")
            } else {
                base.join(net_subdir).join(".cookie")
            }
        });
        Arc::new(RpcClient::with_cookie(&cli.rpcconnect, rpcport, cookie_path))
    };
    let state = Arc::new(Mutex::new(AppState::new()));

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run the app
    let result = run_app(&mut terminal, rpc_client, state);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }

    Ok(())
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    rpc: Arc<RpcClient>,
    state: Arc<Mutex<AppState>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;

    // Spawn poller task
    let poll_state = Arc::clone(&state);
    let poll_rpc = Arc::clone(&rpc);
    rt.spawn(async move {
        poller(poll_rpc, poll_state).await;
    });

    // Render loop
    let tick_rate = Duration::from_millis(250);

    loop {
        // Draw
        {
            let st = state.lock().unwrap();
            terminal.draw(|f| {
                if st.show_help {
                    ui::help::draw(f, &st);
                } else if st.show_reorgs {
                    ui::reorgs::draw(f, &st);
                } else if !st.connected {
                    let area = f.area();
                    f.render_widget(ui::connecting_paragraph(st.stale, st.startup_status.as_deref()), area);
                } else {
                    match st.active_mode() {
                        ViewMode::Ibd => ui::ibd::draw(f, &st),
                        ViewMode::Steady => ui::steady::draw(f, &st),
                    }
                }
            })?;
        }

        // Handle input (50ms timeout)
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()? {
                let mut st = state.lock().unwrap();
                match key.code {
                    KeyCode::Char('q') => {
                        if st.show_help { st.show_help = false; }
                        else if st.show_reorgs { st.show_reorgs = false; }
                        else { return Ok(()); }
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    KeyCode::Char('h') | KeyCode::Char('?') => {
                        st.show_reorgs = false;
                        st.show_help = !st.show_help;
                    }
                    KeyCode::Char('r') => {
                        st.show_help = false;
                        st.show_reorgs = !st.show_reorgs;
                    }
                    KeyCode::Esc => {
                        if st.show_help { st.show_help = false; }
                        if st.show_reorgs { st.show_reorgs = false; }
                    }
                    KeyCode::Char('1') => st.toggle_mode(ViewMode::Ibd),
                    KeyCode::Char('2') => st.toggle_mode(ViewMode::Steady),
                    KeyCode::Up => {
                        if st.selected_peer > 0 {
                            st.selected_peer -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if st.selected_peer + 1 < st.peers.len() {
                            st.selected_peer += 1;
                        }
                    }
                    _ => {}
                }
        }

        // Check stale
        {
            let mut st = state.lock().unwrap();
            st.check_stale();
        }

        // Sleep remainder of tick
        std::thread::sleep(tick_rate.saturating_sub(Duration::from_millis(50)));
    }
}

async fn poller(rpc: Arc<RpcClient>, state: Arc<Mutex<AppState>>) {
    let mut fast_interval = interval(Duration::from_millis(1500));
    let mut slow_counter: u32 = 0;
    let mut ibd_counter: u32 = 0;

    loop {
        fast_interval.tick().await;
        slow_counter += 1;
        ibd_counter += 1;

        // Fast polls (every 1.5s) — lightweight RPCs only
        let (chain_res, peers_res, mempool_res, conn_res, sysinfo_res) = tokio::join!(
            rpc.get_blockchain_info(),
            rpc.get_peer_info(),
            rpc.get_mempool_info(),
            rpc.get_connection_count(),
            rpc.get_system_info(),
        );

        // IBD progress poll (every 3s = every 2nd fast tick) — heavier bitmap RPC
        let ibd_res = if ibd_counter >= 2 {
            ibd_counter = 0;
            Some(rpc.get_ibd_progress().await)
        } else {
            None
        };

        let need_startup_check = {
            let mut st = state.lock().unwrap();

            let any_ok = chain_res.is_ok();

            if let Ok(v) = chain_res {
                st.update_chain_info(&v);
            }
            if let Ok(v) = peers_res {
                st.update_peers(&v);
            }
            if let Ok(v) = mempool_res {
                st.update_mempool_info(&v);
            }
            if let Ok(v) = conn_res {
                st.update_connections(&v);
            }
            if let Some(Ok(v)) = ibd_res {
                st.update_ibd_progress(&v);
            }
            if let Ok(v) = sysinfo_res {
                st.update_system_info(&v);
            }

            if any_ok {
                st.mark_poll();
                st.startup_status = None;
                false
            } else {
                st.connected = false;
                true
            }
        }; // st dropped here, before any .await

        // Try getstartupinfo when main RPCs fail — satd may be loading
        if need_startup_check
            && let Ok(v) = rpc.get_startup_info().await {
                let mut st = state.lock().unwrap();
                st.startup_status = v.get("status")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string());
        }

        // Slow polls (every ~5s = 3-4 fast ticks)
        let is_steady = {
            let st = state.lock().unwrap();
            !st.is_ibd
        };

        if slow_counter >= 3 && is_steady {
            slow_counter = 0;

            let (fees_res, mining_res, txstats_res, uptime_res, blockstats_res, rawmempool_res, utxo_res, reorgs_res) = tokio::join!(
                rpc.estimate_fees(),
                rpc.get_mining_info(),
                rpc.get_chain_tx_stats(),
                rpc.get_uptime(),
                async {
                    let height = state.lock().unwrap().blocks;
                    if height > 0 { rpc.get_block_stats(height).await } else { Err(rpc::RpcError::Rpc("no blocks".into())) }
                },
                rpc.get_raw_mempool_verbose(),
                rpc.get_tx_out_set_info(),
                rpc.get_reorg_history(),
            );

            let mut st = state.lock().unwrap();
            if let Ok(v) = fees_res { st.update_fee_estimates(&v); }
            if let Ok(v) = mining_res { st.update_mining_info(&v); }
            if let Ok(v) = txstats_res { st.update_chain_tx_stats(&v); }
            if let Ok(v) = uptime_res { st.update_uptime(&v); }
            if let Ok(v) = blockstats_res { st.update_block_stats(&v); }
            if let Ok(v) = rawmempool_res { st.update_mempool_dist(&v); }
            if let Ok(v) = utxo_res { st.update_utxo_info(&v); }
            if let Ok(v) = reorgs_res { st.update_reorg_history(&v); }
        }
    }
}
