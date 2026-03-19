use bitcoin::Network;
use std::net::SocketAddr;

use super::peer::PeerAddr;

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

/// Hardcoded .onion seed nodes for mainnet (Bitcoin Core chainparamsseeds.h).
/// These are well-known, reliable Tor v3 nodes.
const MAINNET_ONION_SEEDS: &[(&str, u16)] = &[
    ("2bqghnldu6mcug4pikzprwhtjjnsyederctvci6klcwzepnjd46ikdqd.onion", 8333),
    ("4lr3w2iyyl5u5l6tosizclykz5ecg7sabjuon5gtiml4pkjurdbhmhid.onion", 8333),
    ("5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion", 8333),
    ("c6oy6as64abru7jv626x6bnrxaqxhmpv2c2bljjgdhmhj5wx7swbraid.onion", 8333),
    ("dz4ioibi5g5h6vghaniashybwjhtk4ts3a7vk5cqda6kxv3damhingid.onion", 8333),
    ("i2r5tbaizb36s3gfuahrexgvhsrhjhu2paqj5je3lzog6hpkoanfmeid.onion", 8333),
    ("lsoyeunwlbfpbarczl5q5grzljd7mkrqpgo5j3zxmauelaoanat7iaid.onion", 8333),
    ("oy4jjez4onqfm7edrbyopfkakdw3mrwvclnn4yta6dvx3pynjgicrrad.onion", 8333),
];

/// Hardcoded .onion seed nodes for signet.
const SIGNET_ONION_SEEDS: &[(&str, u16)] = &[
    ("6megrst422lxzsqvshkqkg6z2zl2f6n532vy7t5hj5xmfoauoygzqad.onion", 38333),
];

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

/// Returns hardcoded .onion seed nodes for the given network.
fn onion_seeds_for_network(network: Network) -> &'static [(&'static str, u16)] {
    match network {
        Network::Bitcoin => MAINNET_ONION_SEEDS,
        Network::Signet => SIGNET_ONION_SEEDS,
        _ => &[],
    }
}

/// Resolve seeds for the given network, returning PeerAddr values.
///
/// When a proxy is configured, uses hardcoded .onion seeds instead of
/// clearnet DNS to avoid DNS leaks through the local network.
pub async fn resolve_seeds(network: Network, proxy: Option<&str>) -> Vec<PeerAddr> {
    if proxy.is_some() {
        // Tor mode: use hardcoded .onion seeds to avoid DNS leaks
        let onion_seeds = onion_seeds_for_network(network);
        if onion_seeds.is_empty() {
            tracing::debug!("No .onion seeds configured for network {}", network);
            return Vec::new();
        }
        tracing::info!(
            count = onion_seeds.len(),
            "Using .onion seed nodes (proxy mode, no DNS leak)"
        );
        return onion_seeds
            .iter()
            .map(|(host, port)| PeerAddr::Onion {
                host: host.to_string(),
                port: *port,
            })
            .collect();
    }

    // Clearnet: normal DNS resolution
    resolve_dns_seeds(network)
        .await
        .into_iter()
        .map(PeerAddr::Socket)
        .collect()
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

    #[test]
    fn test_onion_seeds_mainnet() {
        let seeds = onion_seeds_for_network(Network::Bitcoin);
        assert!(!seeds.is_empty());
        for (host, port) in seeds {
            assert!(host.ends_with(".onion"));
            assert_eq!(*port, 8333);
        }
    }

    #[test]
    fn test_onion_seeds_regtest_empty() {
        assert!(onion_seeds_for_network(Network::Regtest).is_empty());
    }

    #[tokio::test]
    async fn test_resolve_seeds_proxy_returns_onion() {
        let addrs = resolve_seeds(Network::Bitcoin, Some("127.0.0.1:9050")).await;
        assert!(!addrs.is_empty());
        for addr in &addrs {
            assert!(addr.is_onion());
        }
    }
}
