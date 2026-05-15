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
    /// Diagnostics for operators. Read-only; outputs are humans-first
    /// tables, with `--output json` available for scripting.
    Debug {
        #[command(subcommand)]
        sub: DebugCmd,
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
enum DebugCmd {
    /// Audit `blk*.dat` slack — compares every `block_index` reference
    /// against the on-disk file sizes and reports per-file referenced vs
    /// total bytes. Read-only; safe on a live node. Cost on mainnet is
    /// ~one minute.
    BlockfileAudit,
}

#[derive(Subcommand, Debug)]
enum NodeCmd {
    /// Process status: uptime, RSS, threads, cache state.
    Status,
    /// Network info.
    Network,
    /// Version string.
    Version,
    /// Effective configuration (post-merge of CLI + conf file + profile).
    Config,
    /// Recent reorg history from the persistent reorg log.
    Reorgs {
        /// Window in seconds (default: 86400 = 24h).
        #[arg(long, default_value = "86400")]
        since: u64,
    },
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
            // `getnetworkinfo` carries the version/subversion/protocolversion
            // triple that operators actually mean when they ask "what version?"
            // — the renderer extracts just those fields in pretty mode below.
            NodeCmd::Version => ("getnetworkinfo".into(), vec![]),
            NodeCmd::Config => ("getconfig".into(), vec![]),
            NodeCmd::Reorgs { since } => ("getreorghistory".into(), vec![json!(since)]),
            NodeCmd::Stop => ("stop".into(), vec![]),
        },
        Cmd::Debug { sub } => match sub {
            DebugCmd::BlockfileAudit => ("getblockfileaudit".into(), vec![]),
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
    print!("{}", render_to_string(cmd, result, output));
}

/// Pure string-returning sibling of `render_result`. Exists so unit tests
/// can exercise the format logic (especially the sats-vs-btc detection in
/// `mempool top`) without driving stdout.
fn render_to_string(cmd: &Cmd, result: &serde_json::Value, output: &OutputFormat) -> String {
    match output {
        OutputFormat::Raw => {
            if let Some(s) = result.as_str() {
                return format!("{}\n", s);
            }
            return result.to_string();
        }
        OutputFormat::Json => {
            return format!("{}\n", serde_json::to_string_pretty(result).unwrap());
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
        return render_mempool_top(obj, *limit);
    }

    // `debug blockfile-audit` — pretty table of per-file slack.
    if let Cmd::Debug {
        sub: DebugCmd::BlockfileAudit,
    } = cmd
    {
        return render_blockfile_audit(result);
    }

    // `node version` — extract just the version fields from getnetworkinfo.
    if let Cmd::Node {
        sub: NodeCmd::Version,
    } = cmd
    {
        let version = result["version"].as_i64();
        let subversion = result["subversion"].as_str();
        let protocol = result["protocolversion"].as_i64();
        if let (Some(v), Some(s), Some(p)) = (version, subversion, protocol) {
            return format!(
                "version:         {}\nsubversion:      {}\nprotocolversion: {}\n",
                v, s, p
            );
        }
        // Fall through to JSON if the response shape isn't what we expect.
    }

    if let Some(s) = result.as_str() {
        format!("{}\n", s)
    } else {
        format!("{}\n", serde_json::to_string_pretty(result).unwrap())
    }
}

/// Render the `mempool top` response as a pretty table. Auto-detects the
/// server's amount unit (integer satoshis vs BTC float) from the first
/// entry's `fees.base` type and labels the column accordingly, so the
/// table always reflects the wire values exactly — never the off-by-1e8
/// confusion that would happen if the CLI always assumed BTC.
fn render_mempool_top(obj: &serde_json::Map<String, serde_json::Value>, limit: usize) -> String {
    let sats_mode = obj
        .values()
        .next()
        .and_then(|v| v.get("fees")?.get("base"))
        .is_some_and(|v| v.is_u64() || v.is_i64());

    let mut entries: Vec<(&String, &serde_json::Value)> = obj.iter().collect();
    entries.sort_by(|a, b| {
        let fee_a = a.1["fees"]["base"].as_f64().unwrap_or(0.0);
        let fee_b = b.1["fees"]["base"].as_f64().unwrap_or(0.0);
        fee_b
            .partial_cmp(&fee_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let fee_header = if sats_mode { "fee_sats" } else { "fee_btc" };
    let mut out = format!("{:<64}  {:>8}  {:>14}\n", "txid", "vsize", fee_header);
    for (txid, entry) in entries.iter().take(limit) {
        let vsize = entry["vsize"].as_u64().unwrap_or(0);
        if sats_mode {
            let fee = entry["fees"]["base"].as_u64().unwrap_or(0);
            out.push_str(&format!("{:<64}  {:>8}  {:>14}\n", txid, vsize, fee));
        } else {
            let fee = entry["fees"]["base"].as_f64().unwrap_or(0.0);
            out.push_str(&format!("{:<64}  {:>8}  {:>14.8}\n", txid, vsize, fee));
        }
    }
    out
}

/// Render the `getblockfileaudit` response as a per-file slack table.
/// Falls through to JSON if the response shape isn't what we expect, so
/// older daemons or unfamiliar fields still display useful output.
fn render_blockfile_audit(result: &serde_json::Value) -> String {
    let Some(files) = result.get("files").and_then(|v| v.as_array()) else {
        return format!("{}\n", serde_json::to_string_pretty(result).unwrap());
    };
    let totals = result.get("totals").cloned().unwrap_or(serde_json::Value::Null);
    let blocks_dir = result
        .get("blocks_dir")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let duration_ms = result
        .get("duration_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let unresolved = result
        .get("unresolved_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let mut out = String::new();
    out.push_str(&format!(
        "blocks_dir: {}\nduration:   {:.2}s\nunresolved: {}\n\n",
        blocks_dir,
        duration_ms as f64 / 1000.0,
        unresolved
    ));
    out.push_str(&format!(
        "{:>8}  {:>12}  {:>12}  {:>12}  {:>6}  {:>10}\n",
        "file_no", "size_MB", "referenced_MB", "slack_MB", "slack%", "blocks"
    ));
    for f in files {
        let file_no = f.get("file_no").and_then(|v| v.as_u64()).unwrap_or(0);
        let size = f.get("file_size").and_then(|v| v.as_u64()).unwrap_or(0);
        let referenced = f.get("referenced_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let slack = f.get("slack_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let blocks = f
            .get("indexed_block_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let pct = if size > 0 {
            (slack as f64 / size as f64) * 100.0
        } else {
            0.0
        };
        out.push_str(&format!(
            "{:>8}  {:>12.1}  {:>12.1}  {:>12.1}  {:>5.1}%  {:>10}\n",
            file_no,
            size as f64 / 1_048_576.0,
            referenced as f64 / 1_048_576.0,
            slack as f64 / 1_048_576.0,
            pct,
            blocks
        ));
    }

    if let Some(t) = totals.as_object() {
        let size = t.get("file_bytes_total").and_then(|v| v.as_u64()).unwrap_or(0);
        let referenced = t
            .get("referenced_bytes_total")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let slack = t.get("slack_bytes_total").and_then(|v| v.as_i64()).unwrap_or(0);
        let file_count = t.get("file_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let pct = if size > 0 {
            (slack as f64 / size as f64) * 100.0
        } else {
            0.0
        };
        out.push_str(&format!(
            "\nTOTAL ({} files): size={:.2} GB, referenced={:.2} GB, slack={:.2} GB ({:.1}%)\n",
            file_count,
            size as f64 / 1_073_741_824.0,
            referenced as f64 / 1_073_741_824.0,
            slack as f64 / 1_073_741_824.0,
            pct
        ));
        let trailing = t
            .get("trailing_slack_total")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let gap = t.get("gap_slack_total").and_then(|v| v.as_u64()).unwrap_or(0);
        out.push_str(&format!(
            "  trailing slack: {:.2} GB  |  gap slack: {:.2} GB\n",
            trailing as f64 / 1_073_741_824.0,
            gap as f64 / 1_073_741_824.0
        ));
    }
    out
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
            // `--version` and `--help` come back as `Err` from
            // `try_parse_from`; clap's `print()` writes the
            // requested output to the right stream and we exit 0.
            // Without this branch the help/version output would be
            // emitted as a parse-error and sat-cli would exit 1.
            use clap::error::ErrorKind;
            if matches!(
                e.kind(),
                ErrorKind::DisplayVersion | ErrorKind::DisplayHelp
            ) {
                e.print().ok();
                std::process::exit(0);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mempool_top_cmd(limit: usize) -> Cmd {
        Cmd::Mempool {
            sub: MempoolCmd::Top { limit },
        }
    }

    #[test]
    fn mempool_top_btc_mode_uses_float_column() {
        // When fees.base is a float (server in default btc mode), the CLI
        // labels the column `fee_btc` and formats with 8 decimal places.
        let body = json!({
            "abc": {
                "vsize": 250u64,
                "weight": 1000u64,
                "time": 0u64,
                "fees": { "base": 0.00012345 },
            },
            "def": {
                "vsize": 100u64,
                "weight": 400u64,
                "time": 0u64,
                "fees": { "base": 0.00100000 },
            },
        });
        let rendered = render_to_string(&mempool_top_cmd(10), &body, &OutputFormat::Pretty);
        assert!(
            rendered.contains("fee_btc"),
            "btc-mode header must say fee_btc, got:\n{}",
            rendered
        );
        // Higher-fee tx sorts first.
        let def_pos = rendered.find("def").expect("def row missing");
        let abc_pos = rendered.find("abc").expect("abc row missing");
        assert!(
            def_pos < abc_pos,
            "higher-feerate (def) row should sort above lower (abc):\n{}",
            rendered
        );
        // Float formatting applied.
        assert!(rendered.contains("0.00100000"));
        // And crucially, no integer sats leaked out.
        assert!(!rendered.contains("fee_sats"));
    }

    #[test]
    fn mempool_top_sats_mode_uses_integer_column() {
        // When fees.base is an integer (server in --rpcdefaultunits=sats
        // mode), the CLI must switch to `fee_sats` and print the raw
        // integer satoshis — NOT format them as a BTC float, which would
        // silently multiply the displayed number by 1e8.
        let body = json!({
            "abc": {
                "vsize": 250u64,
                "weight": 1000u64,
                "time": 0u64,
                "fees": { "base": 12345u64 },
            },
            "def": {
                "vsize": 100u64,
                "weight": 400u64,
                "time": 0u64,
                "fees": { "base": 100000u64 },
            },
        });
        let rendered = render_to_string(&mempool_top_cmd(10), &body, &OutputFormat::Pretty);
        assert!(
            rendered.contains("fee_sats"),
            "sats-mode header must say fee_sats, got:\n{}",
            rendered
        );
        assert!(
            !rendered.contains("fee_btc"),
            "sats-mode must not label the column fee_btc, got:\n{}",
            rendered
        );
        // Raw integer sats appear verbatim.
        assert!(
            rendered.contains("100000") && rendered.contains("12345"),
            "integer sats should be rendered verbatim, got:\n{}",
            rendered
        );
        // Float formatting must NOT appear (the 1e8-shift bug the review caught).
        assert!(
            !rendered.contains("0.00012345"),
            "sats-mode must not format as BTC float (would be 1e8× wrong): {}",
            rendered
        );
    }

    #[test]
    fn mempool_top_limit_truncates() {
        let body = json!({
            "a": {"vsize": 100, "weight": 400, "time": 0, "fees": {"base": 1.0}},
            "b": {"vsize": 100, "weight": 400, "time": 0, "fees": {"base": 2.0}},
            "c": {"vsize": 100, "weight": 400, "time": 0, "fees": {"base": 3.0}},
        });
        let rendered = render_to_string(&mempool_top_cmd(1), &body, &OutputFormat::Pretty);
        // Only the highest-fee row makes it under limit=1.
        assert!(rendered.contains("c"));
        assert!(!rendered.contains("\na  "));
        assert!(!rendered.contains("\nb  "));
    }

    #[test]
    fn node_version_extracts_version_fields() {
        let body = json!({
            "version": 270000,
            "subversion": "/satd:0.1.0/",
            "protocolversion": 70016,
            "localservices": "0000000000000409",
        });
        let cmd = Cmd::Node { sub: NodeCmd::Version };
        let rendered = render_to_string(&cmd, &body, &OutputFormat::Pretty);
        assert!(rendered.contains("version:         270000"));
        assert!(rendered.contains("subversion:      /satd:0.1.0/"));
        assert!(rendered.contains("protocolversion: 70016"));
        // Regression against the original bug where this mapped to `uptime`:
        // that would have produced a bare integer. Make sure we're not doing that.
        assert!(
            rendered.trim().parse::<u64>().is_err(),
            "node version must not render as a bare integer; got: {:?}",
            rendered
        );
    }
}
