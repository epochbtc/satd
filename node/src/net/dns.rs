use bitcoin::Network;
use std::net::SocketAddr;

/// DNS seeds for the Bitcoin mainnet.
const MAINNET_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
];

/// DNS seeds for Bitcoin testnet.
const TESTNET_SEEDS: &[&str] = &[
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.net",
    "testnet-seed.bluematt.me",
];

/// DNS seeds for Bitcoin signet.
const SIGNET_SEEDS: &[&str] = &[
    "seed.signet.bitcoin.sprovoost.nl",
];

/// DNS seeds for regtest (none - local network only).
const REGTEST_SEEDS: &[&str] = &[];

/// Returns the default P2P port for the given network.
fn default_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8333,
        Network::Testnet => 18333,
        Network::Signet => 38333,
        Network::Regtest => 18444,
        _ => 8333,
    }
}

/// Returns the DNS seed list for the given network.
fn seeds_for_network(network: Network) -> &'static [&'static str] {
    match network {
        Network::Bitcoin => MAINNET_SEEDS,
        Network::Testnet => TESTNET_SEEDS,
        Network::Signet => SIGNET_SEEDS,
        Network::Regtest => REGTEST_SEEDS,
        _ => &[],
    }
}

/// Resolve DNS seeds for the given network, returning a list of socket
/// addresses (IP + default P2P port). Returns an empty vec if all lookups
/// fail or no seeds are configured (e.g. regtest).
pub async fn resolve_dns_seeds(network: Network) -> Vec<SocketAddr> {
    let seeds = seeds_for_network(network);
    let port = default_port(network);

    if seeds.is_empty() {
        tracing::debug!("No DNS seeds configured for network {}", network);
        return Vec::new();
    }

    let mut addrs = Vec::new();

    for seed in seeds {
        let host = format!("{}:{}", seed, port);
        match tokio::net::lookup_host(&host).await {
            Ok(resolved) => {
                let before = addrs.len();
                addrs.extend(resolved);
                let found = addrs.len() - before;
                tracing::debug!(seed, found, "DNS seed resolved");
            }
            Err(e) => {
                tracing::warn!(seed, "DNS seed lookup failed: {}", e);
            }
        }
    }

    tracing::info!(
        count = addrs.len(),
        seeds = seeds.len(),
        "DNS seed resolution complete"
    );

    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seeds_for_network() {
        assert_eq!(seeds_for_network(Network::Bitcoin).len(), 8);
        assert_eq!(seeds_for_network(Network::Testnet).len(), 3);
        assert_eq!(seeds_for_network(Network::Signet).len(), 1);
        assert!(seeds_for_network(Network::Regtest).is_empty());
    }

    #[test]
    fn test_default_port() {
        assert_eq!(default_port(Network::Bitcoin), 8333);
        assert_eq!(default_port(Network::Testnet), 18333);
        assert_eq!(default_port(Network::Signet), 38333);
        assert_eq!(default_port(Network::Regtest), 18444);
    }
}
