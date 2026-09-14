//! Server configuration and the policy decisions that depend only on it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network, ScriptBuf};

use super::vardiff::VardiffConfig;

/// Everything the Stratum server needs from the node's configuration.
#[derive(Debug, Clone)]
pub struct StratumConfig {
    pub network: Network,
    /// Plaintext Stratum V1 listener.
    pub bind: SocketAddr,
    /// TLS Stratum V1 listener.
    pub tls_bind: Option<SocketAddr>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Require a client certificate on the TLS listener.
    pub mtls: bool,
    pub mtls_client_ca: Option<PathBuf>,
    /// CN / DNS-SAN names accepted from a client certificate. Empty accepts
    /// any certificate the CA signed.
    pub mtls_client_allow: Vec<String>,
    /// Payout script for a miner whose username is not an address.
    pub fallback_address: Option<ScriptBuf>,
    pub initial_difficulty: u64,
    /// Connection cap across every listener.
    pub max_conns: usize,
    pub vardiff: VardiffConfig,
    /// The Stratum V2 listener, when configured. Needs the `stratum-v2`
    /// feature; without it, binding fails.
    pub v2: Option<V2Config>,
}

/// The Stratum V2 listener's settings.
#[derive(Debug, Clone)]
pub struct V2Config {
    pub bind: SocketAddr,
    /// The authority key file; created if absent.
    pub key_path: PathBuf,
    /// Channels one connection may open.
    pub max_channels: usize,
    /// Serve Stratum V2 Job Declaration.
    pub job_declaration: bool,
}

/// The initial share difficulty when none is configured.
///
/// Mainnet's is sized for a small ASIC — a ~1 TH/s device finds a
/// difficulty-10,000 share about every 35 seconds; vardiff adjusts from
/// there. Signet has no entry because the server refuses to run on it.
pub fn default_initial_difficulty(network: Network) -> u64 {
    match network {
        Network::Bitcoin => 10_000,
        Network::Regtest => 1,
        _ => 1_000,
    }
}

/// Whether the server should hand out work.
///
/// Not during initial block download: the tip is days or years behind, and
/// every block found on it is a stale block. Regtest is exempt, because a
/// fresh regtest chain's genesis is from 2011 and it would never leave IBD
/// otherwise — the same exception `generatetoaddress` makes.
pub fn should_issue_work(network: Network, initial_block_download: bool) -> bool {
    network == Network::Regtest || !initial_block_download
}

/// A miner's resolved payout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payout {
    pub script: ScriptBuf,
    /// The address the username named, or `None` when the fallback was used.
    pub address: Option<String>,
    /// The worker name after the first `.`, kept for logs only.
    pub worker: Option<String>,
}

/// The username named no usable address and there is no fallback.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("username is not a valid address for this network and no --stratumaddress is set")]
pub struct PayoutError;

/// Resolve a `mining.authorize` username to a payout script.
///
/// The username is `<address>` or `<address>.<worker>`. An address for the
/// wrong network does not count: `require_network` compares the network
/// *kind*, so a mainnet address is refused on every test network and a test
/// address on mainnet, but one test network's address is accepted on
/// another (they share an encoding). Without a usable address, `fallback`
/// pays.
pub fn resolve_payout(
    username: &str,
    network: Network,
    fallback: Option<&ScriptBuf>,
) -> Result<Payout, PayoutError> {
    let (name, worker) = match username.split_once('.') {
        Some((n, w)) => (n, Some(w.to_string())),
        None => (username, None),
    };
    let parsed = Address::<NetworkUnchecked>::from_str(name)
        .ok()
        .and_then(|a| a.require_network(network).ok());
    match (parsed, fallback) {
        (Some(addr), _) => Ok(Payout {
            script: addr.script_pubkey(),
            address: Some(addr.to_string()),
            worker,
        }),
        (None, Some(script)) => Ok(Payout { script: script.clone(), address: None, worker }),
        (None, None) => Err(PayoutError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(network: Network) -> String {
        Address::p2wsh(&ScriptBuf::new_op_return([7]), network).to_string()
    }

    #[test]
    fn username_suffix_is_worker_not_address() {
        let regtest_addr = addr(Network::Regtest);
        let p = resolve_payout(&format!("{regtest_addr}.rig1"), Network::Regtest, None).unwrap();
        assert_eq!(p.address.as_deref(), Some(regtest_addr.as_str()));
        assert_eq!(p.worker.as_deref(), Some("rig1"));
        // Only the first dot splits.
        let p = resolve_payout(&format!("{regtest_addr}.a.b"), Network::Regtest, None).unwrap();
        assert_eq!(p.worker.as_deref(), Some("a.b"));
        let p = resolve_payout(&regtest_addr, Network::Regtest, None).unwrap();
        assert_eq!(p.worker, None);
    }

    #[test]
    fn wrong_network_address_rejected() {
        let mainnet_addr = addr(Network::Bitcoin);
        assert_eq!(resolve_payout(&mainnet_addr, Network::Regtest, None), Err(PayoutError));
        assert_eq!(resolve_payout("not-an-address", Network::Regtest, None), Err(PayoutError));

        let fallback = ScriptBuf::new_op_return([1]);
        let p = resolve_payout(&mainnet_addr, Network::Regtest, Some(&fallback)).unwrap();
        assert_eq!(p.script, fallback, "the fallback pays, not the foreign address");
        assert_eq!(p.address, None);
    }

    #[test]
    fn work_is_withheld_during_ibd_except_regtest() {
        assert!(should_issue_work(Network::Regtest, true));
        assert!(should_issue_work(Network::Regtest, false));
        for net in [Network::Bitcoin, Network::Testnet, Network::Testnet4] {
            assert!(!should_issue_work(net, true), "{net}");
            assert!(should_issue_work(net, false), "{net}");
        }
    }
}
