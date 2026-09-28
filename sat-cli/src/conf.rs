//! `bitcoin.conf` reading for the client: which chain, which port, which
//! credentials — resolved the way `satd` resolves them for the server side, so
//! `sat-cli` finds the node a given config file describes without any flags.
//!
//! The daemon's rules this mirrors (`satd/src/config.rs`):
//!
//! - **Chain:** a command-line selector (`-chain=`, `-regtest`, `-testnet`,
//!   `-testnet4`, `-signet`) wins; otherwise the file's global-scope `chain=`
//!   or a bare `regtest=1` / `testnet=1` / `testnet4=1` / `signet=1`. More
//!   than one selector on either side is an error.
//! - **Sections:** `[main]`, `[test]`, `[testnet4]`, `[signet]`, `[regtest]`.
//!   A key in the active chain's section beats the same key in the global
//!   scope, and within one scope the **first** occurrence wins (Bitcoin Core's
//!   config-file precedence). A top-level `rpcport=` applies on every chain,
//!   as it does for the daemon.
//! - **Credentials:** Bitcoin Core's `bitcoin-cli` rule. `rpcuser` and
//!   `rpcpassword` are looked up independently (command line, then file); a
//!   non-empty password means user/password authentication, an empty one
//!   means the cookie file. The daemon writes no cookie when both are set in
//!   its config, so reading them here is what makes that setup reachable.
//!
//! Unknown keys are ignored: this is a client reading a server's file, and
//! `bitcoin-cli` reads its config with invalid keys ignored too.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The chains satd runs on, with the per-chain names and defaults the client
/// needs. Kept local so the CLI does not link the node crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Main,
    Test,
    Testnet4,
    Signet,
    Regtest,
}

impl Chain {
    /// Parse a `-chain=` value. Accepts the names the daemon accepts.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "main" | "mainnet" | "bitcoin" => Ok(Chain::Main),
            "test" | "testnet" | "testnet3" => Ok(Chain::Test),
            "testnet4" => Ok(Chain::Testnet4),
            "signet" => Ok(Chain::Signet),
            "regtest" => Ok(Chain::Regtest),
            other => Err(format!(
                "unknown chain {other:?}. Accepted values: main, test, testnet4, signet, regtest."
            )),
        }
    }

    /// The `bitcoin.conf` section that applies on this chain.
    pub fn section(self) -> &'static str {
        match self {
            Chain::Main => "main",
            Chain::Test => "test",
            Chain::Testnet4 => "testnet4",
            Chain::Signet => "signet",
            Chain::Regtest => "regtest",
        }
    }

    /// The per-chain data subdirectory (none on mainnet).
    pub fn subdir(self) -> Option<&'static str> {
        match self {
            Chain::Main => None,
            Chain::Test => Some("testnet3"),
            Chain::Testnet4 => Some("testnet4"),
            Chain::Signet => Some("signet"),
            Chain::Regtest => Some("regtest"),
        }
    }

    pub fn default_rpc_port(self) -> u16 {
        match self {
            Chain::Main => 8332,
            Chain::Test => 18332,
            Chain::Testnet4 => 48332,
            Chain::Signet => 38332,
            Chain::Regtest => 18443,
        }
    }

    /// The chain name an HWI-compatible external signer takes in `--chain`.
    pub fn signer_name(self) -> &'static str {
        match self {
            Chain::Main => "main",
            Chain::Test | Chain::Testnet4 => "test",
            Chain::Signet => "signet",
            Chain::Regtest => "regtest",
        }
    }
}

/// A parsed `bitcoin.conf`: the global scope and each `[section]`, with every
/// value of a repeated key kept in file order.
#[derive(Debug, Default)]
pub struct ConfFile {
    global: HashMap<String, Vec<String>>,
    sections: HashMap<String, HashMap<String, Vec<String>>>,
}

impl ConfFile {
    pub fn parse(content: &str) -> Self {
        let mut file = ConfFile::default();
        let mut section: Option<String> = None;
        for line in content.lines() {
            // Whole-line comments only, as the daemon parses them: a `#`
            // later on a line is part of the value (a password may hold one).
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = Some(line[1..line.len() - 1].trim().to_string());
                continue;
            }
            let (key, value) = match line.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (line, "1"),
            };
            let map = match &section {
                Some(s) => file.sections.entry(s.clone()).or_default(),
                None => &mut file.global,
            };
            map.entry(key.to_string()).or_default().push(value.to_string());
        }
        file
    }

    /// Read `path`. A missing file is not an error (`Ok(None)`); an
    /// unreadable one is, when the caller named it with `-conf`.
    pub fn read(path: &Path) -> std::io::Result<Option<Self>> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(Some(Self::parse(&s))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// First value of `key` in the chain's section, else the first in the
    /// global scope.
    pub fn get(&self, chain: Chain, key: &str) -> Option<&str> {
        self.sections
            .get(chain.section())
            .and_then(|s| s.get(key))
            .and_then(|v| v.first())
            .or_else(|| self.global.get(key).and_then(|v| v.first()))
            .map(String::as_str)
    }

    /// The chain the file's global scope selects, if any.
    pub fn chain(&self) -> Result<Option<Chain>, String> {
        let named = self
            .global
            .get("chain")
            .and_then(|v| v.last())
            .map(|v| Chain::parse(v))
            .transpose()?;
        let mut bare: Option<Chain> = None;
        for (key, chain) in [
            ("regtest", Chain::Regtest),
            ("testnet", Chain::Test),
            ("testnet4", Chain::Testnet4),
            ("signet", Chain::Signet),
        ] {
            let on = self
                .global
                .get(key)
                .and_then(|v| v.last())
                .is_some_and(|v| is_true(v));
            if on {
                match bare {
                    Some(prev) if prev != chain => {
                        return Err("config file selects more than one chain; set only one of \
                             regtest/testnet/testnet4/signet (or use chain=)"
                            .to_string());
                    }
                    _ => bare = Some(chain),
                }
            }
        }
        match (named, bare) {
            (Some(a), Some(b)) if a != b => Err(
                "config file sets both chain= and a conflicting chain selector; set only one"
                    .to_string(),
            ),
            (a, b) => Ok(a.or(b)),
        }
    }
}

fn is_true(v: &str) -> bool {
    matches!(v, "1" | "true" | "yes")
}

/// What the command line said, before the config file is consulted.
#[derive(Debug, Default, Clone)]
pub struct CliConn {
    pub chain: Option<String>,
    pub regtest: bool,
    pub testnet: bool,
    pub testnet4: bool,
    pub signet: bool,
    pub rpcconnect: Option<String>,
    pub rpcport: Option<u16>,
    pub rpcuser: Option<String>,
    pub rpcpassword: Option<String>,
    pub rpccookiefile: Option<PathBuf>,
}

impl CliConn {
    /// The chain the command line selects, or an error for more than one.
    pub fn chain(&self) -> Result<Option<Chain>, String> {
        let mut picked: Vec<Chain> = Vec::new();
        if let Some(name) = &self.chain {
            picked.push(Chain::parse(name)?);
        }
        for (on, chain) in [
            (self.regtest, Chain::Regtest),
            (self.testnet, Chain::Test),
            (self.testnet4, Chain::Testnet4),
            (self.signet, Chain::Signet),
        ] {
            if on {
                picked.push(chain);
            }
        }
        if picked.len() > 1 {
            return Err(
                "Invalid combination of -regtest, -signet, -testnet, -testnet4 and -chain. \
                 Can use at most one."
                    .to_string(),
            );
        }
        Ok(picked.pop())
    }
}

/// How to authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Creds {
    UserPass(String, String),
    Cookie(PathBuf),
}

/// Everything the client needs to reach the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub chain: Chain,
    pub host: String,
    pub port: u16,
    pub creds: Creds,
    /// The config file that was read, for error messages.
    pub conf_path: PathBuf,
}

/// Resolve the connection from the command line plus `conf` (the parsed
/// config file, if one exists). `base_datadir` is `-datadir` or the default.
pub fn resolve(
    cli: &CliConn,
    conf: Option<&ConfFile>,
    base_datadir: &Path,
    conf_path: PathBuf,
) -> Result<Conn, String> {
    let chain = match cli.chain()? {
        Some(c) => c,
        None => conf.map(ConfFile::chain).transpose()?.flatten().unwrap_or(Chain::Main),
    };
    let from_file = |key: &str| conf.and_then(|c| c.get(chain, key)).map(str::to_string);

    let host = cli
        .rpcconnect
        .clone()
        .or_else(|| from_file("rpcconnect"))
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let port = match cli.rpcport {
        Some(p) => p,
        None => match from_file("rpcport") {
            Some(v) => v
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("Invalid port provided in -rpcport: {v}"))?,
            None => chain.default_rpc_port(),
        },
    };

    let net_datadir = match chain.subdir() {
        Some(sub) => base_datadir.join(sub),
        None => base_datadir.to_path_buf(),
    };
    let password = cli.rpcpassword.clone().or_else(|| from_file("rpcpassword"));
    let creds = match password.filter(|p| !p.is_empty()) {
        Some(pass) => {
            let user = cli
                .rpcuser
                .clone()
                .or_else(|| from_file("rpcuser"))
                .unwrap_or_default();
            Creds::UserPass(user, pass)
        }
        None => {
            let cookie = cli
                .rpccookiefile
                .clone()
                .or_else(|| from_file("rpccookiefile").map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from(".cookie"));
            // Relative cookie paths are under the chain's data directory,
            // as for bitcoin-cli.
            let cookie = if cookie.is_absolute() {
                cookie
            } else {
                net_datadir.join(cookie)
            };
            Creds::Cookie(cookie)
        }
    };

    Ok(Conn {
        chain,
        host,
        port,
        creds,
        conf_path,
    })
}

/// Where the config file is: `-conf` (relative to the data directory, as in
/// Bitcoin Core) or `<datadir>/bitcoin.conf`.
pub fn conf_path(cli_conf: Option<&Path>, base_datadir: &Path) -> PathBuf {
    match cli_conf {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => base_datadir.join(p),
        None => base_datadir.join("bitcoin.conf"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve_str(cli: &CliConn, body: &str) -> Result<Conn, String> {
        let conf = ConfFile::parse(body);
        resolve(cli, Some(&conf), Path::new("/d"), PathBuf::from("/d/bitcoin.conf"))
    }

    /// The flat file Warnet's chart renders for a node image whose version it
    /// does not treat as sectioned: chain selector, credentials and port all
    /// at the top level.
    const WARNET_FLAT: &str = "regtest=1\ncheckmempool=0\nrpcuser=user\nrpcallowip=0.0.0.0/0\n\
        rpcbind=0.0.0.0\nrest=1\nrpcport=18443\nrpcpassword=gn0cchi\ndebug=rpc\n";

    #[test]
    fn flat_file_gives_chain_port_and_password() {
        let c = resolve_str(&CliConn::default(), WARNET_FLAT).unwrap();
        assert_eq!(c.chain, Chain::Regtest);
        assert_eq!(c.port, 18443);
        assert_eq!(c.creds, Creds::UserPass("user".into(), "gn0cchi".into()));
    }

    #[test]
    fn a_top_level_rpcport_applies_off_mainnet() {
        let c = resolve_str(&CliConn::default(), "regtest=1\nrpcport=19000\n").unwrap();
        assert_eq!(c.port, 19000);
        let c = resolve_str(&CliConn::default(), "signet=1\nrpcport=19001\n").unwrap();
        assert_eq!((c.chain, c.port), (Chain::Signet, 19001));
    }

    #[test]
    fn the_chain_section_beats_the_global_scope() {
        let body = "regtest=1\nrpcport=1\nrpcuser=g\nrpcpassword=gp\n\
                    [regtest]\nrpcport=2\nrpcuser=r\nrpcpassword=rp\n[main]\nrpcport=3\n";
        let c = resolve_str(&CliConn::default(), body).unwrap();
        assert_eq!(c.port, 2);
        assert_eq!(c.creds, Creds::UserPass("r".into(), "rp".into()));
    }

    #[test]
    fn another_chains_section_is_ignored() {
        let body = "regtest=1\n[test]\nrpcport=5\nrpcpassword=x\n";
        let c = resolve_str(&CliConn::default(), body).unwrap();
        assert_eq!(c.port, 18443);
        assert_eq!(c.creds, Creds::Cookie(PathBuf::from("/d/regtest/.cookie")));
    }

    #[test]
    fn the_first_value_in_a_scope_wins() {
        let c = resolve_str(&CliConn::default(), "rpcport=10\nrpcport=11\n").unwrap();
        assert_eq!(c.port, 10);
    }

    #[test]
    fn the_command_line_beats_the_file_key_by_key() {
        let cli = CliConn {
            rpcport: Some(7),
            rpcuser: Some("cliuser".into()),
            ..Default::default()
        };
        let c = resolve_str(&cli, WARNET_FLAT).unwrap();
        assert_eq!(c.port, 7);
        // The password still comes from the file: bitcoin-cli looks each up
        // on its own.
        assert_eq!(c.creds, Creds::UserPass("cliuser".into(), "gn0cchi".into()));
    }

    #[test]
    fn no_password_means_the_cookie() {
        let c = resolve_str(&CliConn::default(), "rpcuser=only\n").unwrap();
        assert_eq!(c.creds, Creds::Cookie(PathBuf::from("/d/.cookie")));
        let c = resolve_str(&CliConn::default(), "rpcuser=u\nrpcpassword=\n").unwrap();
        assert_eq!(c.creds, Creds::Cookie(PathBuf::from("/d/.cookie")));
    }

    #[test]
    fn a_relative_cookie_file_is_under_the_chain_datadir() {
        let c = resolve_str(&CliConn::default(), "signet=1\nrpccookiefile=auth/c\n").unwrap();
        assert_eq!(c.creds, Creds::Cookie(PathBuf::from("/d/signet/auth/c")));
        let c = resolve_str(&CliConn::default(), "rpccookiefile=/abs/c\n").unwrap();
        assert_eq!(c.creds, Creds::Cookie(PathBuf::from("/abs/c")));
    }

    #[test]
    fn chain_selection_from_the_file() {
        for (body, chain) in [
            ("chain=signet\n", Chain::Signet),
            ("testnet4=1\n", Chain::Testnet4),
            ("testnet=1\n", Chain::Test),
            ("regtest=0\n", Chain::Main),
            ("", Chain::Main),
            // A selector inside a section is not a selector.
            ("[regtest]\nregtest=1\n", Chain::Main),
        ] {
            assert_eq!(resolve_str(&CliConn::default(), body).unwrap().chain, chain, "{body:?}");
        }
        assert!(resolve_str(&CliConn::default(), "regtest=1\nsignet=1\n").is_err());
        assert!(resolve_str(&CliConn::default(), "chain=main\nregtest=1\n").is_err());
    }

    #[test]
    fn the_command_line_chain_beats_the_file() {
        let cli = CliConn {
            signet: true,
            ..Default::default()
        };
        let c = resolve_str(&cli, WARNET_FLAT).unwrap();
        assert_eq!((c.chain, c.port), (Chain::Signet, 18443));
        let cli = CliConn {
            chain: Some("testnet4".into()),
            ..Default::default()
        };
        assert_eq!(resolve_str(&cli, "").unwrap().port, 48332);
    }

    #[test]
    fn two_command_line_chains_are_refused() {
        let cli = CliConn {
            regtest: true,
            chain: Some("signet".into()),
            ..Default::default()
        };
        let e = resolve_str(&cli, "").unwrap_err();
        assert!(e.contains("Can use at most one"), "{e}");
        assert!(resolve_str(
            &CliConn {
                chain: Some("nope".into()),
                ..Default::default()
            },
            ""
        )
        .is_err());
    }

    #[test]
    fn a_bad_file_port_is_an_error_not_a_default() {
        assert!(resolve_str(&CliConn::default(), "rpcport=abc\n").is_err());
        assert!(resolve_str(&CliConn::default(), "rpcport=0\n").is_err());
    }

    #[test]
    fn rpcconnect_from_the_file() {
        let c = resolve_str(&CliConn::default(), "rpcconnect=tank0\n").unwrap();
        assert_eq!(c.host, "tank0");
        assert_eq!(resolve_str(&CliConn::default(), "").unwrap().host, "127.0.0.1");
    }

    #[test]
    fn comments_and_bare_keys() {
        let body = "# a comment\nregtest\nrpcport=9\nrpcpassword=a#b\n";
        let c = resolve_str(&CliConn::default(), body).unwrap();
        assert_eq!((c.chain, c.port), (Chain::Regtest, 9));
        assert_eq!(c.creds, Creds::UserPass(String::new(), "a#b".into()));
    }

    #[test]
    fn conf_path_rules() {
        let d = Path::new("/d");
        assert_eq!(conf_path(None, d), PathBuf::from("/d/bitcoin.conf"));
        assert_eq!(conf_path(Some(Path::new("x.conf")), d), PathBuf::from("/d/x.conf"));
        assert_eq!(conf_path(Some(Path::new("/e/x.conf")), d), PathBuf::from("/e/x.conf"));
    }
}
