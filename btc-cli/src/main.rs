use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "btc-cli", version, about = "Bitcoin Core-compatible RPC client")]
struct CliArgs {
    #[arg(long, help = "Use regtest network")]
    regtest: bool,

    #[arg(long, help = "Use testnet network")]
    testnet: bool,

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

    #[arg(long, help = "Data directory (for locating cookie file)")]
    datadir: Option<PathBuf>,

    #[arg(long, help = "Wait for server to start")]
    rpcwait: bool,

    /// RPC method name
    method: String,

    /// RPC parameters
    params: Vec<String>,
}

/// Convert single-dash flags to double-dash for clap compatibility.
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

#[tokio::main]
async fn main() {
    let raw_args: Vec<String> = std::env::args().collect();
    let normalized = normalize_args(raw_args);
    let cli = match CliArgs::try_parse_from(normalized) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let rpcport = cli.rpcport.unwrap_or_else(|| {
        if cli.regtest {
            18443
        } else if cli.testnet {
            18332
        } else {
            8332
        }
    });

    // Resolve authentication credentials
    let (auth_user, auth_pass) = if let (Some(user), Some(pass)) = (&cli.rpcuser, &cli.rpcpassword)
    {
        (user.clone(), pass.clone())
    } else {
        // Read cookie file
        let cookie_path = cli.rpccookiefile.unwrap_or_else(|| {
            let base = cli
                .datadir
                .clone()
                .unwrap_or_else(|| default_datadir());
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
                // If rpcwait, we'll retry until the cookie file appears
                ("".to_string(), "".to_string())
            }
        }
    };

    let url = format!("http://{}:{}/", cli.rpcconnect, rpcport);

    // Parse positional params as JSON values, falling back to strings
    let params: Vec<serde_json::Value> = cli
        .params
        .iter()
        .map(|p| serde_json::from_str(p).unwrap_or_else(|_| serde_json::Value::String(p.clone())))
        .collect();

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "btc-cli",
        "method": cli.method,
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

                if let Some(error) = response_body.get("error") {
                    if !error.is_null() {
                        let msg = error
                            .get("message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("Unknown error");
                        let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
                        eprintln!("error code: {}: {}", code, msg);
                        std::process::exit(1);
                    }
                }

                if let Some(result) = response_body.get("result") {
                    if let Some(s) = result.as_str() {
                        println!("{}", s);
                    } else {
                        println!("{}", serde_json::to_string_pretty(result).unwrap());
                    }
                }
                break;
            }
            Err(e) => {
                if cli.rpcwait && is_connection_error(&e) {
                    // Retry: re-read cookie file in case btcd just started
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
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read cookie file: {}", e))?;
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
