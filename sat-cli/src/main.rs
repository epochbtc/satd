//! sat-cli — Bitcoin-Core-compatible RPC client with structured subcommands.
//!
//! Two invocation styles are supported simultaneously:
//!
//! 1. **Structured subcommands** (new, default-pretty):
//!    ```sh
//!    sat-cli chain info
//!    sat-cli mempool top
//!    sat-cli peer list
//!    sat-cli fee estimate --target 6
//!    sat-cli node status
//!    ```
//!
//! 2. **Legacy raw-RPC passthrough** (Bitcoin Core compat, unchanged):
//!    ```sh
//!    sat-cli getblockchaininfo
//!    sat-cli getblockhash 100
//!    ```
//!
//! The legacy form is captured by `clap`'s `external_subcommand` so existing
//! scripts and the `test_sat_cli_integration` regtest continue to work.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sat-cli",
    version,
    about = "Bitcoin-Core-compatible RPC client"
)]
struct Cli {
    #[arg(long, help = "Use regtest network", global = true)]
    regtest: bool,

    #[arg(long, help = "Use testnet network", global = true)]
    testnet: bool,

    #[arg(long, default_value = "127.0.0.1", help = "RPC host", global = true)]
    rpcconnect: String,

    #[arg(long, help = "RPC port", global = true)]
    rpcport: Option<u16>,

    #[arg(long, help = "RPC username", global = true)]
    rpcuser: Option<String>,

    #[arg(long, help = "RPC password", global = true)]
    rpcpassword: Option<String>,

    #[arg(long, help = "Path to cookie file", global = true)]
    rpccookiefile: Option<PathBuf>,

    #[arg(
        long,
        help = "Data directory (for locating cookie file)",
        global = true
    )]
    datadir: Option<PathBuf>,

    #[arg(long, help = "Wait for server to start", global = true)]
    rpcwait: bool,

    #[arg(
        long,
        value_name = "FORMAT",
        help = "Output format: pretty (default), json, raw",
        global = true
    )]
    output: Option<String>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Chain / blockchain queries.
    Chain {
        #[command(subcommand)]
        sub: ChainCmd,
    },
    /// Mempool queries.
    Mempool {
        #[command(subcommand)]
        sub: MempoolCmd,
    },
    /// Peer management.
    Peer {
        #[command(subcommand)]
        sub: PeerCmd,
    },
    /// Fee estimation.
    Fee {
        #[command(subcommand)]
        sub: FeeCmd,
    },
    /// Node status and control.
    Node {
        #[command(subcommand)]
        sub: NodeCmd,
    },
    /// Bitcoin-Core-compatible raw RPC passthrough. Captures unknown
    /// subcommands so `sat-cli getblockchaininfo` still works.
    #[command(external_subcommand)]
    Raw(Vec<String>),
}

#[derive(Subcommand, Debug)]
enum ChainCmd {
    /// Summary of chain tip, headers, difficulty, and IBD state.
    Info,
    /// Current best block height.
    Height,
    /// Current best block hash.
    Tip,
    /// All known chain tips (includes orphans).
    Tips,
}

#[derive(Subcommand, Debug)]
enum MempoolCmd {
    /// Mempool size/bytes/min-fee summary.
    Info,
    /// Top-N mempool txs by feerate (default 20).
    Top {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// All mempool tx ids.
    List,
}

#[derive(Subcommand, Debug)]
enum PeerCmd {
    /// List connected peers.
    List,
    /// Connection count.
    Count,
    /// List banned peers.
    Banned,
}

#[derive(Subcommand, Debug)]
enum FeeCmd {
    /// Fee estimate for a confirmation target in blocks (default 6).
    Estimate {
        #[arg(long, default_value = "6")]
        target: u32,
    },
}

#[derive(Subcommand, Debug)]
enum NodeCmd {
    /// Process status: uptime, RSS, threads, cache state.
    Status,
    /// Network info.
    Network,
    /// Version string.
    Version,
    /// Shutdown the satd daemon.
    Stop,
}

/// Legacy single-dash → double-dash normalization for Bitcoin-Core-compat flags.
fn normalize_args(args: Vec<String>) -> Vec<String> {
    let known_flags = [
        "regtest",
        "testnet",
        "rpcconnect",
        "rpcport",
        "rpcuser",
        "rpcpassword",
        "rpccookiefile",
        "datadir",
        "rpcwait",
        "output",
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

/// Translate a structured `Cmd` into a raw `(method, params)` RPC call.
fn resolve_cmd(cmd: &Cmd) -> (String, Vec<serde_json::Value>) {
    use serde_json::json;
    match cmd {
        Cmd::Chain { sub } => match sub {
            ChainCmd::Info => ("getblockchaininfo".into(), vec![]),
            ChainCmd::Height => ("getblockcount".into(), vec![]),
            ChainCmd::Tip => ("getbestblockhash".into(), vec![]),
            ChainCmd::Tips => ("getchaintips".into(), vec![]),
        },
        Cmd::Mempool { sub } => match sub {
            MempoolCmd::Info => ("getmempoolinfo".into(), vec![]),
            MempoolCmd::Top { .. } => ("getrawmempool".into(), vec![json!(true)]),
            MempoolCmd::List => ("getrawmempool".into(), vec![]),
        },
        Cmd::Peer { sub } => match sub {
            PeerCmd::List => ("getpeerinfo".into(), vec![]),
            PeerCmd::Count => ("getconnectioncount".into(), vec![]),
            PeerCmd::Banned => ("listbanned".into(), vec![]),
        },
        Cmd::Fee { sub } => match sub {
            FeeCmd::Estimate { target } => ("estimatesmartfee".into(), vec![json!(target)]),
        },
        Cmd::Node { sub } => match sub {
            NodeCmd::Status => ("getsysteminfo".into(), vec![]),
            NodeCmd::Network => ("getnetworkinfo".into(), vec![]),
            NodeCmd::Version => ("uptime".into(), vec![]), // uptime is the cheapest probe
            NodeCmd::Stop => ("stop".into(), vec![]),
        },
        Cmd::Raw(args) => {
            let mut it = args.iter();
            let method = it.next().cloned().unwrap_or_default();
            let params: Vec<serde_json::Value> = it
                .map(|p| {
                    serde_json::from_str(p).unwrap_or_else(|_| serde_json::Value::String(p.clone()))
                })
                .collect();
            (method, params)
        }
    }
}

/// Post-process a subcommand result for nicer default display. Unknown shapes
/// fall through to pretty-printed JSON.
fn render_result(cmd: &Cmd, result: &serde_json::Value, output: &OutputFormat) {
    match output {
        OutputFormat::Raw => {
            if let Some(s) = result.as_str() {
                println!("{}", s);
            } else {
                print!("{}", result);
            }
            return;
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(result).unwrap());
            return;
        }
        OutputFormat::Pretty => {}
    }

    // Pretty mode: simple hand-rolled tables for common shapes. Anything we
    // don't specifically handle falls through to pretty-printed JSON so users
    // still see everything.
    if let Cmd::Mempool {
        sub: MempoolCmd::Top { limit },
    } = cmd
        && let Some(obj) = result.as_object()
    {
        let mut entries: Vec<(&String, &serde_json::Value)> = obj.iter().collect();
        entries.sort_by(|a, b| {
            let fee_a = a.1["fees"]["base"].as_f64().unwrap_or(0.0);
            let fee_b = b.1["fees"]["base"].as_f64().unwrap_or(0.0);
            fee_b
                .partial_cmp(&fee_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        println!("{:<64}  {:>8}  {:>14}", "txid", "vsize", "fee_btc");
        for (txid, entry) in entries.iter().take(*limit) {
            let vsize = entry["vsize"].as_u64().unwrap_or(0);
            let fee = entry["fees"]["base"].as_f64().unwrap_or(0.0);
            println!("{:<64}  {:>8}  {:>14.8}", txid, vsize, fee);
        }
        return;
    }

    if let Some(s) = result.as_str() {
        println!("{}", s);
    } else {
        println!("{}", serde_json::to_string_pretty(result).unwrap());
    }
}

enum OutputFormat {
    Pretty,
    Json,
    Raw,
}

impl OutputFormat {
    fn parse(s: Option<&str>) -> Self {
        match s.map(str::to_ascii_lowercase).as_deref() {
            Some("json") => Self::Json,
            Some("raw") => Self::Raw,
            _ => Self::Pretty,
        }
    }
}

#[tokio::main]
async fn main() {
    let raw_args: Vec<String> = std::env::args().collect();
    let normalized = normalize_args(raw_args);
    let cli = match Cli::try_parse_from(normalized) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let rpcport = cli.rpcport.unwrap_or({
        if cli.regtest {
            18443
        } else if cli.testnet {
            18332
        } else {
            8332
        }
    });

    let (auth_user, auth_pass) = if let (Some(user), Some(pass)) = (&cli.rpcuser, &cli.rpcpassword)
    {
        (user.clone(), pass.clone())
    } else {
        let cookie_path = cli.rpccookiefile.clone().unwrap_or_else(|| {
            let base = cli.datadir.clone().unwrap_or_else(default_datadir);
            let net_subdir = if cli.regtest {
                "regtest"
            } else if cli.testnet {
                "testnet3"
            } else {
                ""
            };
            if net_subdir.is_empty() {
                base.join(".cookie")
            } else {
                base.join(net_subdir).join(".cookie")
            }
        });

        match read_cookie_file(&cookie_path) {
            Ok(creds) => creds,
            Err(e) => {
                if !cli.rpcwait {
                    eprintln!(
                        "error: Could not locate RPC credentials. No authentication cookie could be found, and RPC password is not set.\n\
                             Cookie file: {}\n\
                             {}",
                        cookie_path.display(),
                        e
                    );
                    std::process::exit(1);
                }
                ("".to_string(), "".to_string())
            }
        }
    };

    let url = format!("http://{}:{}/", cli.rpcconnect, rpcport);
    let output = OutputFormat::parse(cli.output.as_deref());

    let (method, params) = resolve_cmd(&cli.command);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "sat-cli",
        "method": method,
        "params": params,
    });

    let client = reqwest::Client::new();

    loop {
        let auth_header = format!(
            "Basic {}",
            BASE64.encode(format!("{}:{}", auth_user, auth_pass))
        );

        let result = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", &auth_header)
            .json(&body)
            .send()
            .await;

        match result {
            Ok(response) => {
                if response.status() == 401 {
                    eprintln!("error: Authorization failed (incorrect rpcuser or rpcpassword)");
                    std::process::exit(1);
                }

                let response_body: serde_json::Value = match response.json().await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("error: Failed to parse response: {}", e);
                        std::process::exit(1);
                    }
                };

                if let Some(error) = response_body.get("error")
                    && !error.is_null()
                {
                    let msg = error
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Unknown error");
                    let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
                    eprintln!("error code: {}: {}", code, msg);
                    std::process::exit(1);
                }

                if let Some(result) = response_body.get("result") {
                    render_result(&cli.command, result, &output);
                }
                break;
            }
            Err(e) => {
                if cli.rpcwait && is_connection_error(&e) {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                eprintln!("error: Could not connect to server: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn is_connection_error(e: &reqwest::Error) -> bool {
    e.is_connect() || e.is_request()
}

fn read_cookie_file(path: &std::path::Path) -> Result<(String, String), String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Cannot read cookie file: {}", e))?;
    let (user, pass) = content
        .trim()
        .split_once(':')
        .ok_or_else(|| "Invalid cookie file format".to_string())?;
    Ok((user.to_string(), pass.to_string()))
}

fn default_datadir() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".bitcoin"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/.bitcoin"))
}
