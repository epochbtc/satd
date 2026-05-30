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
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{interval, Duration};

use rpc::{RpcClient, RpcError};
use state::{AppState, RpcFailure, ViewMode};

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
            let st = state.lock();
            terminal.draw(|f| {
                if st.show_help {
                    ui::help::draw(f, &st);
                } else if st.show_reorgs {
                    ui::reorgs::draw(f, &st);
                } else if !st.connected {
                    if st.startup_status.is_some() {
                        ui::startup::draw(f, &st);
                    } else {
                        let area = f.area();
                        f.render_widget(ui::connecting_paragraph(st.stale), area);
                    }
                } else {
                    match st.active_mode() {
                        ViewMode::Ibd => ui::ibd::draw(f, &st),
                        ViewMode::Steady => ui::steady::draw(f, &st),
                        ViewMode::Mempool => ui::mempool::draw(f, &st),
                        ViewMode::Chain => ui::chain::draw(f, &st),
                    }
                }
                // Draw warnings modal LAST so it overlays every other view.
                // Respects per-id dismissal so acknowledged warnings don't
                // block the view until they re-trigger.
                ui::warnings::draw(f, &st);
                // Failure modal sits on top of warnings — if we can't
                // reach satd at all, surface that before anything from
                // the (now-stale) node state.
                ui::failure::draw(f, &st);
            })?;
        }

        // Handle input (50ms timeout)
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()? {
                let mut st = state.lock();
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
                    KeyCode::Char('a') => {
                        // Acknowledge & dismiss currently-visible warnings
                        // for this session. They'll reappear if the
                        // node clears and re-records them, or a new
                        // id surfaces.
                        st.dismiss_visible_warnings();
                    }
                    KeyCode::Char('w') => {
                        // Re-show dismissed warnings (operator wants to
                        // look at them again).
                        st.dismissed_warnings.clear();
                    }
                    KeyCode::Esc => {
                        if st.show_help { st.show_help = false; }
                        if st.show_reorgs { st.show_reorgs = false; }
                    }
                    KeyCode::Char('1') => st.toggle_mode(ViewMode::Ibd),
                    KeyCode::Char('2') => st.toggle_mode(ViewMode::Steady),
                    KeyCode::Char('3') => st.toggle_mode(ViewMode::Mempool),
                    KeyCode::Char('4') => st.toggle_mode(ViewMode::Chain),
                    KeyCode::Up => match st.active_mode() {
                        ViewMode::Mempool => {
                            if st.selected_mempool_row > 0 {
                                st.selected_mempool_row -= 1;
                            }
                        }
                        _ => {
                            if st.selected_peer > 0 {
                                st.selected_peer -= 1;
                            }
                        }
                    },
                    KeyCode::Down => match st.active_mode() {
                        ViewMode::Mempool => {
                            if st.selected_mempool_row + 1 < st.mempool_top.len() {
                                st.selected_mempool_row += 1;
                            }
                        }
                        _ => {
                            if st.selected_peer + 1 < st.peers.len() {
                                st.selected_peer += 1;
                            }
                        }
                    },
                    _ => {}
                }
        }

        // Check stale
        {
            let mut st = state.lock();
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
        let (chain_res, peers_res, mempool_res, conn_res, sysinfo_res, warnings_res) = tokio::join!(
            rpc.get_blockchain_info(),
            rpc.get_peer_info(),
            rpc.get_mempool_info(),
            rpc.get_connection_count(),
            rpc.get_system_info(),
            rpc.get_warnings(),
        );

        // IBD progress poll (every 3s = every 2nd fast tick) — heavier bitmap RPC
        let ibd_res = if ibd_counter >= 2 {
            ibd_counter = 0;
            Some(rpc.get_ibd_progress().await)
        } else {
            None
        };

        // The cookie-read state is the root cause of a 401, so snapshot it
        // before locking state and let it refine an `AuthFailed` into the
        // specific cookie error below (it does not override connect/timeout
        // failures — see `resolve_failure`).
        let cookie_error = rpc.cookie_error();

        let need_startup_check = {
            let mut st = state.lock();

            let any_ok = chain_res.is_ok();

            // Classify the failure mode BEFORE the per-result Ok-moves
            // below — once we move the inner Values out, the original
            // Results can't be borrowed again. Only used when `any_ok`
            // is false, but computing unconditionally is cheap.
            let batch_failure = resolve_failure(
                cookie_error,
                classify_batch_error(&[
                    chain_res.as_ref().err(),
                    peers_res.as_ref().err(),
                    mempool_res.as_ref().err(),
                    conn_res.as_ref().err(),
                    sysinfo_res.as_ref().err(),
                    warnings_res.as_ref().err(),
                ]),
            );

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
            if let Ok(v) = warnings_res {
                st.update_warnings(&v);
            }

            if any_ok {
                st.mark_poll();
                st.clear_startup();
                st.clear_failure();
                false
            } else {
                st.connected = false;
                if let Some((kind, msg)) = batch_failure {
                    st.record_failure(kind, msg);
                }
                true
            }
        }; // st dropped here, before any .await

        // Try getstartupinfo when main RPCs fail — satd may be loading
        if need_startup_check
            && let Ok(v) = rpc.get_startup_info().await {
                let status = state::StartupStatus::from_json(&v);
                let mut st = state.lock();
                st.update_startup(status);
        }

        // Slow polls (every ~5s = 3-4 fast ticks).
        let is_steady = {
            let st = state.lock();
            !st.is_ibd
        };

        if slow_counter >= 3 {
            slow_counter = 0;

            // Index + server-status polls always run, regardless of IBD
            // state — they drive the always-visible services row, which
            // operators may force-display via key 2 even during IBD.
            let (index_res, srv_res) =
                tokio::join!(rpc.get_index_info(), rpc.get_server_status());
            {
                let mut st = state.lock();
                if let Ok(v) = index_res {
                    st.update_index_info(&v);
                }
                if let Ok(v) = srv_res {
                    st.update_server_status(&v);
                }
            }

            // Heavy steady-state batch — only meaningful at chain tip.
            // Skipped during IBD because most fields would be nullish.
            if is_steady {
                let (fees_res, mining_res, txstats_res, uptime_res, blockstats_res, rawmempool_res, utxo_res, reorgs_res, mhist_res) = tokio::join!(
                    rpc.estimate_fees(),
                    rpc.get_mining_info(),
                    rpc.get_chain_tx_stats(),
                    rpc.get_uptime(),
                    async {
                        let height = state.lock().blocks;
                        if height > 0 { rpc.get_block_stats(height).await } else { Err(rpc::RpcError::Rpc("no blocks".into())) }
                    },
                    rpc.get_raw_mempool_verbose(),
                    rpc.get_tx_out_set_info(),
                    rpc.get_reorg_history(),
                    rpc.get_mempool_history(),
                );

                {
                    let mut st = state.lock();
                    if let Ok(v) = fees_res { st.update_fee_estimates(&v); }
                    if let Ok(v) = mining_res { st.update_mining_info(&v); }
                    if let Ok(v) = txstats_res { st.update_chain_tx_stats(&v); }
                    if let Ok(v) = uptime_res { st.update_uptime(&v); }
                    if let Ok(v) = blockstats_res { st.update_block_stats(&v); }
                    if let Ok(v) = rawmempool_res { st.update_mempool_dist(&v); }
                    if let Ok(v) = utxo_res { st.update_utxo_info(&v); }
                    if let Ok(v) = reorgs_res { st.update_reorg_history(&v); }
                    if let Ok(v) = mhist_res { st.update_mempool_history(&v); }
                }

                // Refresh the difficulty-epoch anchor when the floor advances —
                // ≈ once per fortnight in steady state. Two cheap RPCs.
                let anchor_target = {
                    let st = state.lock();
                    let cur = st.blocks - (st.blocks % 2016);
                    if st.blocks > 0 && st.epoch_start_height != Some(cur) {
                        Some(cur)
                    } else {
                        None
                    }
                };
                if let Some(epoch_h) = anchor_target
                    && let Ok(hash_v) = rpc.get_block_hash(epoch_h).await
                    && let Some(hash_str) = hash_v.as_str()
                    && let Ok(hdr_v) = rpc.get_block_header(hash_str).await
                {
                    state.lock().update_epoch_anchor(epoch_h, &hdr_v);
                }
            }
        }
    }
}

/// Fold the cookie-read state into the batch classification. An unreadable
/// cookie is the root cause of an *auth* failure — we reached satd and it
/// returned 401 because the credentials we sent were empty/stale — so in
/// that case we surface the specific, actionable cookie error (e.g.
/// "Permission denied", with cookie-side remediation) and its exact OS
/// message instead of the generic 401. It clears automatically:
/// `RpcClient::refresh_auth` re-reads the cookie on each auth failure, so
/// once satd relaxes it to `0640` at READY the next good poll dismisses the
/// modal.
///
/// Crucially this only overrides `AuthFailed`. A `ConnectionFailed` /
/// `Timeout` means we couldn't even talk to satd, and the cookie being
/// missing there is a *symptom* of satd being down (it hasn't created the
/// file yet), not the cause — so the "is satd running?" diagnosis must win.
fn resolve_failure(
    cookie_error: Option<String>,
    batch: Option<(RpcFailure, String)>,
) -> Option<(RpcFailure, String)> {
    match (cookie_error, &batch) {
        (Some(msg), Some((RpcFailure::AuthFailed, _))) => {
            Some((RpcFailure::CookieUnreadable, msg))
        }
        _ => batch,
    }
}

/// Pick the most informative error from a fast-poll batch. Auth/connect
/// failures take priority — they're the actionable ones that should
/// trigger the modal immediately. Timeouts and Rpc errors come behind.
/// Returns `None` if no errors were passed in.
fn classify_batch_error(errs: &[Option<&RpcError>]) -> Option<(RpcFailure, String)> {
    let mut best: Option<(u8, RpcFailure, String)> = None;
    for e in errs.iter().copied().flatten() {
        let (prio, kind) = match e {
            RpcError::AuthFailed => (3, RpcFailure::AuthFailed),
            RpcError::ConnectionFailed => (2, RpcFailure::ConnectionFailed),
            RpcError::Timeout => (1, RpcFailure::Timeout),
            RpcError::Request(_) | RpcError::Rpc(_) => (0, RpcFailure::Other),
        };
        if best.as_ref().is_none_or(|(p, _, _)| prio > *p) {
            best = Some((prio, kind, e.to_string()));
        }
    }
    best.map(|(_, k, m)| (k, m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_prefers_auth_over_connection_over_timeout() {
        let conn = RpcError::ConnectionFailed;
        let auth = RpcError::AuthFailed;
        let timeout = RpcError::Timeout;
        let other = RpcError::Rpc("boom".into());

        // AuthFailed always wins.
        let (k, _) = classify_batch_error(&[
            Some(&conn),
            Some(&timeout),
            Some(&auth),
            Some(&other),
        ])
        .unwrap();
        assert_eq!(k, RpcFailure::AuthFailed);

        // Without auth, ConnectionFailed wins over Timeout / Other.
        let (k, _) = classify_batch_error(&[Some(&timeout), Some(&conn), Some(&other)]).unwrap();
        assert_eq!(k, RpcFailure::ConnectionFailed);

        // Without auth/connect, Timeout wins over Other.
        let (k, _) = classify_batch_error(&[Some(&other), Some(&timeout)]).unwrap();
        assert_eq!(k, RpcFailure::Timeout);

        // All-None batch yields None.
        assert!(classify_batch_error(&[None, None]).is_none());
    }

    #[test]
    fn cookie_error_refines_auth_failure() {
        // Reached satd, got 401, cookie unreadable: surface the real cookie
        // error (with its OS message) instead of the generic 401.
        let (k, msg) = resolve_failure(
            Some("Cannot read cookie file: Permission denied (os error 13)".into()),
            Some((RpcFailure::AuthFailed, "Authentication failed".into())),
        )
        .unwrap();
        assert_eq!(k, RpcFailure::CookieUnreadable);
        assert!(msg.contains("Permission denied"));
    }

    #[test]
    fn cookie_error_does_not_mask_connection_failure() {
        // satd is down: the missing cookie is a symptom, not the cause. The
        // "is satd running?" diagnosis must win over a misleading cookie modal.
        let r = resolve_failure(
            Some("Cannot read cookie file: No such file or directory".into()),
            Some((RpcFailure::ConnectionFailed, "refused".into())),
        );
        assert_eq!(r.unwrap().0, RpcFailure::ConnectionFailed);

        // Same for a timeout.
        let r = resolve_failure(
            Some("Cannot read cookie file: Permission denied".into()),
            Some((RpcFailure::Timeout, "30s".into())),
        );
        assert_eq!(r.unwrap().0, RpcFailure::Timeout);
    }

    #[test]
    fn no_cookie_error_passes_batch_through() {
        // Readable cookie (or user/pass auth): keep the batch classification.
        let r = resolve_failure(None, Some((RpcFailure::ConnectionFailed, "refused".into())));
        assert_eq!(r.unwrap().0, RpcFailure::ConnectionFailed);
        // A readable cookie with a genuine 401 stays AuthFailed (credentials
        // really are wrong — e.g. mismatched --rpcuser/--rpcpassword).
        let r = resolve_failure(None, Some((RpcFailure::AuthFailed, "401".into())));
        assert_eq!(r.unwrap().0, RpcFailure::AuthFailed);
        // No failure at all stays None.
        assert!(resolve_failure(None, None).is_none());
    }
}
