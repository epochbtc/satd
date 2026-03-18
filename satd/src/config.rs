use bitcoin::Network;
use clap::Parser;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Resolved node configuration after merging CLI args, config file, and defaults.
#[derive(Debug, Clone)]
pub struct Config {
    pub network: Network,
    pub datadir: PathBuf,
    pub rpcport: u16,
    pub rpcbind: String,
    pub rpcuser: Option<String>,
    pub rpcpassword: Option<String>,
    pub listen: bool,
    pub port: u16,
    pub connect: Vec<String>,
    pub assumevalid: Option<String>,
    // Mempool policy
    pub mempoolfullrbf: bool,
    pub maxmempool: usize,
    pub minrelaytxfee: u64,
    pub dustrelayfee: u64,
    pub datacarriersize: usize,
    pub datacarrier: bool,
    pub limitancestorcount: usize,
    pub limitdescendantcount: usize,
    pub mempoolexpiry: u64,
    pub permitbaremultisig: bool,
}

impl Config {
    /// Load configuration by merging CLI args → config file → defaults.
    pub fn load() -> Result<Self, String> {
        let raw_args: Vec<String> = std::env::args().collect();
        let normalized = normalize_args(raw_args);
        let cli = CliArgs::try_parse_from(normalized).map_err(|e| e.to_string())?;
        Self::from_cli(cli)
    }

    pub fn from_cli(cli: CliArgs) -> Result<Self, String> {
        // Determine network from CLI flags
        let network = if cli.regtest {
            Network::Regtest
        } else if cli.testnet {
            Network::Testnet
        } else if cli.signet {
            Network::Signet
        } else {
            Network::Bitcoin
        };

        // Determine datadir
        let base_datadir = cli.datadir.unwrap_or_else(default_datadir);

        // Determine config file path and parse it
        let conf_path = cli
            .conf
            .unwrap_or_else(|| base_datadir.join("bitcoin.conf"));
        let config_file = if conf_path.exists() {
            Some(ConfigFile::parse_file(&conf_path)?)
        } else {
            None
        };

        // Section name for the active network
        let section = match network {
            Network::Regtest => "regtest",
            Network::Testnet => "test",
            Network::Bitcoin => "main",
            _ => "main",
        };

        // Helper: look up a key from config file (section first, then global)
        let file_get = |key: &str| -> Option<String> {
            config_file.as_ref().and_then(|cf| {
                cf.sections
                    .get(section)
                    .and_then(|s| s.get(key))
                    .and_then(|v| v.last().cloned())
                    .or_else(|| {
                        cf.global
                            .get(key)
                            .and_then(|v| v.last().cloned())
                    })
            })
        };

        let file_get_all = |key: &str| -> Vec<String> {
            config_file
                .as_ref()
                .map(|cf| {
                    let mut vals = cf.global.get(key).cloned().unwrap_or_default();
                    if let Some(s) = cf.sections.get(section)
                        && let Some(sv) = s.get(key) {
                            vals.extend(sv.iter().cloned());
                        }
                    vals
                })
                .unwrap_or_default()
        };

        // Merge: CLI > config file > defaults
        let rpcport = cli
            .rpcport
            .or_else(|| file_get("rpcport").and_then(|v| v.parse().ok()))
            .unwrap_or_else(|| default_rpc_port(network));

        let rpcbind = file_get("rpcbind").unwrap_or_else(|| "127.0.0.1".to_string());

        let rpcuser = cli.rpcuser.or_else(|| file_get("rpcuser"));
        let rpcpassword = cli.rpcpassword.or_else(|| file_get("rpcpassword"));

        let listen = cli
            .listen
            .or_else(|| file_get("listen").and_then(|v| parse_bool(&v)))
            .unwrap_or(true);

        let port = cli
            .port
            .or_else(|| file_get("port").and_then(|v| v.parse().ok()))
            .unwrap_or_else(|| default_p2p_port(network));

        let mut connect = cli.connect;
        if connect.is_empty() {
            connect = file_get_all("connect");
        }

        let assumevalid = cli.assumevalid.or_else(|| file_get("assumevalid"));

        // Mempool policy: CLI > config file > defaults
        let mempoolfullrbf = cli
            .mempoolfullrbf
            .or_else(|| file_get("mempoolfullrbf").and_then(|v| parse_bool(&v)))
            .unwrap_or(true); // full RBF on by default (matches Bitcoin Core v28+)

        let maxmempool = cli
            .maxmempool
            .or_else(|| file_get("maxmempool").and_then(|v| v.parse().ok()))
            .unwrap_or(300); // MB

        let minrelaytxfee = cli
            .minrelaytxfee
            .or_else(|| file_get("minrelaytxfee").and_then(|v| v.parse().ok()))
            .unwrap_or(1_000); // sat/kvB

        let dustrelayfee = cli
            .dustrelayfee
            .or_else(|| file_get("dustrelayfee").and_then(|v| v.parse().ok()))
            .unwrap_or(3_000); // sat/kvB

        let datacarriersize = cli
            .datacarriersize
            .or_else(|| file_get("datacarriersize").and_then(|v| v.parse().ok()))
            .unwrap_or(83);

        let datacarrier = cli
            .datacarrier
            .or_else(|| file_get("datacarrier").and_then(|v| parse_bool(&v)))
            .unwrap_or(true);

        let limitancestorcount = cli
            .limitancestorcount
            .or_else(|| file_get("limitancestorcount").and_then(|v| v.parse().ok()))
            .unwrap_or(25);

        let limitdescendantcount = cli
            .limitdescendantcount
            .or_else(|| file_get("limitdescendantcount").and_then(|v| v.parse().ok()))
            .unwrap_or(25);

        let mempoolexpiry = cli
            .mempoolexpiry
            .or_else(|| file_get("mempoolexpiry").and_then(|v| v.parse().ok()))
            .unwrap_or(336); // hours

        let permitbaremultisig = cli
            .permitbaremultisig
            .or_else(|| file_get("permitbaremultisig").and_then(|v| parse_bool(&v)))
            .unwrap_or(true);

        // Validate auth consistency
        if rpcuser.is_some() != rpcpassword.is_some() {
            return Err(
                "rpcuser and rpcpassword must both be set or both be unset".to_string(),
            );
        }

        Ok(Config {
            network,
            datadir: base_datadir,
            rpcport,
            rpcbind,
            rpcuser,
            rpcpassword,
            listen,
            port,
            connect,
            assumevalid,
            mempoolfullrbf,
            maxmempool,
            minrelaytxfee,
            dustrelayfee,
            datacarriersize,
            datacarrier,
            limitancestorcount,
            limitdescendantcount,
            mempoolexpiry,
            permitbaremultisig,
        })
    }

    /// Returns the network-specific data directory (e.g. ~/.bitcoin/regtest/).
    pub fn network_datadir(&self) -> PathBuf {
        match self.network {
            Network::Regtest => self.datadir.join("regtest"),
            Network::Testnet => self.datadir.join("testnet3"),
            Network::Signet => self.datadir.join("signet"),
            Network::Bitcoin => self.datadir.clone(),
            _ => self.datadir.clone(),
        }
    }
}

/// CLI arguments compatible with bitcoind flags.
#[derive(Parser, Debug)]
#[command(name = "satd", version, about = "Bitcoin Core-compatible node in Rust")]
pub struct CliArgs {
    #[arg(long, help = "Use regtest network")]
    pub regtest: bool,

    #[arg(long, help = "Use testnet network")]
    pub testnet: bool,

    #[arg(long, help = "Use signet network")]
    pub signet: bool,

    #[arg(long, value_name = "DIR", help = "Data directory")]
    pub datadir: Option<PathBuf>,

    #[arg(long, value_name = "FILE", help = "Config file path")]
    pub conf: Option<PathBuf>,

    #[arg(long, value_name = "PORT", help = "RPC server port")]
    pub rpcport: Option<u16>,

    #[arg(long, value_name = "USER", help = "RPC username")]
    pub rpcuser: Option<String>,

    #[arg(long, value_name = "PASS", help = "RPC password")]
    pub rpcpassword: Option<String>,

    #[arg(long, value_name = "BOOL", help = "Accept P2P connections")]
    pub listen: Option<bool>,

    #[arg(long, value_name = "PORT", help = "P2P listen port")]
    pub port: Option<u16>,

    #[arg(long, value_name = "ADDR", help = "Connect to specific peer")]
    pub connect: Vec<String>,

    #[arg(long, value_name = "HASH", help = "Assume blocks up to this hash are valid (skip script verification)")]
    pub assumevalid: Option<String>,

    // Mempool policy flags (Bitcoin Core compatible + extensions)
    #[arg(long, value_name = "BOOL", help = "Enable full replace-by-fee (default: true)")]
    pub mempoolfullrbf: Option<bool>,

    #[arg(long, value_name = "MB", help = "Maximum mempool size in MB (default: 300)")]
    pub maxmempool: Option<usize>,

    #[arg(long, value_name = "RATE", help = "Minimum relay fee rate in sat/kvB (default: 1000)")]
    pub minrelaytxfee: Option<u64>,

    #[arg(long, value_name = "RATE", help = "Dust relay fee rate in sat/kvB (default: 3000)")]
    pub dustrelayfee: Option<u64>,

    #[arg(long, value_name = "BYTES", help = "Maximum OP_RETURN size in bytes (default: 83, 0 = reject all)")]
    pub datacarriersize: Option<usize>,

    #[arg(long, value_name = "BOOL", help = "Accept OP_RETURN outputs (default: true)")]
    pub datacarrier: Option<bool>,

    #[arg(long, value_name = "N", help = "Maximum unconfirmed ancestor count (default: 25)")]
    pub limitancestorcount: Option<usize>,

    #[arg(long, value_name = "N", help = "Maximum unconfirmed descendant count (default: 25)")]
    pub limitdescendantcount: Option<usize>,

    #[arg(long, value_name = "HOURS", help = "Mempool expiry in hours (default: 336)")]
    pub mempoolexpiry: Option<u64>,

    #[arg(long, value_name = "BOOL", help = "Allow bare multisig outputs (default: true)")]
    pub permitbaremultisig: Option<bool>,
}

/// Convert Bitcoin Core-style single-dash long flags to clap-compatible double-dash.
/// e.g. `-regtest` → `--regtest`, `-datadir=/path` → `--datadir=/path`
pub fn normalize_args(args: Vec<String>) -> Vec<String> {
    // Known long flags that Bitcoin Core accepts with a single dash
    let known_flags = [
        "regtest",
        "testnet",
        "signet",
        "datadir",
        "conf",
        "rpcport",
        "rpcuser",
        "rpcpassword",
        "listen",
        "port",
        "connect",
        "assumevalid",
        "mempoolfullrbf",
        "maxmempool",
        "minrelaytxfee",
        "dustrelayfee",
        "datacarriersize",
        "datacarrier",
        "limitancestorcount",
        "limitdescendantcount",
        "mempoolexpiry",
        "permitbaremultisig",
    ];

    args.into_iter()
        .map(|arg| {
            // Skip the binary name or already double-dashed args
            if !arg.starts_with('-') || arg.starts_with("--") {
                return arg;
            }
            // Strip the single dash
            let rest = &arg[1..];
            // Check if the rest (before any =) matches a known flag
            let flag_name = rest.split('=').next().unwrap_or(rest);
            if known_flags.contains(&flag_name) {
                format!("-{}", arg) // prepend another dash
            } else {
                arg
            }
        })
        .collect()
}

/// Parsed bitcoin.conf file.
#[derive(Debug, Default)]
pub struct ConfigFile {
    pub global: HashMap<String, Vec<String>>,
    pub sections: HashMap<String, HashMap<String, Vec<String>>>,
}

impl ConfigFile {
    pub fn parse_file(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self, String> {
        let mut file = ConfigFile::default();
        let mut current_section: Option<String> = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Section header: [name]
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let name = trimmed[1..trimmed.len() - 1].trim().to_string();
                current_section = Some(name);
                continue;
            }

            // Key=value or bare key
            let (key, value) = if let Some(eq_pos) = trimmed.find('=') {
                let k = trimmed[..eq_pos].trim().to_string();
                let v = trimmed[eq_pos + 1..].trim().to_string();
                (k, v)
            } else {
                (trimmed.to_string(), "1".to_string())
            };

            let map = match &current_section {
                Some(section) => file.sections.entry(section.clone()).or_default(),
                None => &mut file.global,
            };
            map.entry(key).or_default().push(value);
        }

        Ok(file)
    }
}

fn default_datadir() -> PathBuf {
    dirs_home().join(".bitcoin")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn default_rpc_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8332,
        Network::Testnet => 18332,
        Network::Signet => 38332,
        Network::Regtest => 18443,
        _ => 8332,
    }
}

fn default_p2p_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8333,
        Network::Testnet => 18333,
        Network::Signet => 38333,
        Network::Regtest => 18444,
        _ => 8333,
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_args() {
        let args = vec![
            "satd".to_string(),
            "-regtest".to_string(),
            "-datadir=/tmp/test".to_string(),
            "-rpcport".to_string(),
            "18443".to_string(),
        ];
        let normalized = normalize_args(args);
        assert_eq!(normalized[1], "--regtest");
        assert_eq!(normalized[2], "--datadir=/tmp/test");
        assert_eq!(normalized[3], "--rpcport");
    }

    #[test]
    fn test_config_file_parse() {
        let content = r#"
# Global settings
rpcuser=alice
rpcpassword=secret

[regtest]
rpcport=18443
listen=0

[main]
rpcport=8332
"#;
        let cf = ConfigFile::parse(content).unwrap();
        assert_eq!(cf.global.get("rpcuser").unwrap().last().unwrap(), "alice");
        assert_eq!(
            cf.sections.get("regtest").unwrap().get("rpcport").unwrap().last().unwrap(),
            "18443"
        );
        assert_eq!(
            cf.sections.get("main").unwrap().get("rpcport").unwrap().last().unwrap(),
            "8332"
        );
    }

    #[test]
    fn test_config_file_bare_keys() {
        let content = "listen\nserver\n";
        let cf = ConfigFile::parse(content).unwrap();
        assert_eq!(cf.global.get("listen").unwrap().last().unwrap(), "1");
        assert_eq!(cf.global.get("server").unwrap().last().unwrap(), "1");
    }

    #[test]
    fn test_default_ports() {
        assert_eq!(default_rpc_port(Network::Regtest), 18443);
        assert_eq!(default_rpc_port(Network::Bitcoin), 8332);
        assert_eq!(default_p2p_port(Network::Regtest), 18444);
    }

    #[test]
    fn test_config_from_cli_regtest() {
        let cli = CliArgs {
            regtest: true,
            testnet: false,
            signet: false,
            datadir: Some(PathBuf::from("/tmp/satd-test")),
            conf: None,
            rpcport: None,
            rpcuser: None,
            rpcpassword: None,
            listen: None,
            port: None,
            connect: vec![],
            assumevalid: None,
            mempoolfullrbf: None,
            maxmempool: None,
            minrelaytxfee: None,
            dustrelayfee: None,
            datacarriersize: None,
            datacarrier: None,
            limitancestorcount: None,
            limitdescendantcount: None,
            mempoolexpiry: None,
            permitbaremultisig: None,
        };
        let config = Config::from_cli(cli).unwrap();
        assert_eq!(config.network, Network::Regtest);
        assert_eq!(config.rpcport, 18443);
        assert_eq!(config.network_datadir(), PathBuf::from("/tmp/satd-test/regtest"));
        assert!(config.mempoolfullrbf); // full RBF on by default
    }

    #[test]
    fn test_config_auth_validation() {
        let cli = CliArgs {
            regtest: true,
            testnet: false,
            signet: false,
            datadir: Some(PathBuf::from("/tmp/satd-test")),
            conf: None,
            rpcport: None,
            rpcuser: Some("alice".to_string()),
            rpcpassword: None, // missing password
            listen: None,
            port: None,
            connect: vec![],
            assumevalid: None,
            mempoolfullrbf: None,
            maxmempool: None,
            minrelaytxfee: None,
            dustrelayfee: None,
            datacarriersize: None,
            datacarrier: None,
            limitancestorcount: None,
            limitdescendantcount: None,
            mempoolexpiry: None,
            permitbaremultisig: None,
        };
        assert!(Config::from_cli(cli).is_err());
    }
}
