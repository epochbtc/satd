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
    resolve_seeds_with(network, proxy, &[]).await
}

/// Resolve DNS / .onion seeds, prepending any operator-supplied
/// signet seed nodes (Bitcoin Core's `-signetseednode=<host[:port]>`,
/// repeatable). Extra seeds are honoured only on Signet — passing
/// them on other networks has no effect, matching Core's semantics.
/// The extras come BEFORE the built-in seeds so a private-signet
/// operator's nodes get tried first; the built-ins remain as
/// fallback in case the private seeds are down.
pub async fn resolve_seeds_with(
    network: Network,
    proxy: Option<&str>,
    extra_signet_seeds: &[String],
) -> Vec<PeerAddr> {
    let mut prepend: Vec<PeerAddr> = Vec::new();
    if network == Network::Signet {
        let port = default_port(network);
        for seed in extra_signet_seeds {
            // host[:port] — bare host inherits default port. We accept
            // both DNS hostnames and literal IPs; literal .onion
            // addresses are parsed as Onion so they route via the
            // proxy when one is configured.
            let (host, p) = match seed.rsplit_once(':') {
                Some((h, p_str)) if p_str.chars().all(|c| c.is_ascii_digit()) => {
                    let parsed = p_str.parse::<u16>().unwrap_or(port);
                    (h.to_string(), parsed)
                }
                _ => (seed.to_string(), port),
            };
            if host.ends_with(".onion") {
                prepend.push(PeerAddr::Onion { host, port: p });
            } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                prepend.push(PeerAddr::Socket(SocketAddr::new(ip, p)));
            } else {
                // DNS name: resolve here so the rest of the seed
                // pipeline sees concrete sockets. Failures are logged
                // and skipped (matching the behaviour for built-in
                // seeds further down).
                let target = format!("{host}:{p}");
                match tokio::net::lookup_host(&target).await {
                    Ok(resolved) => {
                        for sa in resolved {
                            prepend.push(PeerAddr::Socket(sa));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            seed = %host,
                            "signet seed node lookup failed: {}",
                            e
                        );
                    }
                }
            }
        }
        if !prepend.is_empty() {
            tracing::info!(
                count = prepend.len(),
                "operator-supplied signet seed nodes resolved"
            );
        }
    }

    let builtins: Vec<PeerAddr> = if proxy.is_some() {
        // Tor mode: use hardcoded .onion seeds to avoid DNS leaks
        let onion_seeds = onion_seeds_for_network(network);
        if onion_seeds.is_empty() {
            tracing::debug!("No .onion seeds configured for network {}", network);
            Vec::new()
        } else {
            tracing::info!(
                count = onion_seeds.len(),
                "Using .onion seed nodes (proxy mode, no DNS leak)"
            );
            onion_seeds
                .iter()
                .map(|(host, port)| PeerAddr::Onion {
                    host: host.to_string(),
                    port: *port,
                })
                .collect()
        }
    } else {
        // Clearnet: normal DNS resolution
        resolve_dns_seeds(network)
            .await
            .into_iter()
            .map(PeerAddr::Socket)
            .collect()
    };

    prepend.extend(builtins);
    prepend
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

    #[tokio::test]
    async fn extra_signet_seeds_ignored_off_signet() {
        // Bitcoin Core's -signetseednode is signet-only. On other
        // networks the extras must be ignored so an operator with a
        // single multi-section config can leave `signetseednode=` in
        // the `[signet]` block without contaminating mainnet runs.
        let extras = vec!["192.0.2.5:38333".to_string()];
        let addrs = resolve_seeds_with(Network::Regtest, None, &extras).await;
        // Regtest has no built-in seeds, so this should be empty.
        assert!(addrs.is_empty(), "regtest seeds should be empty");
    }

    #[tokio::test]
    async fn extra_signet_seeds_literal_ipv4_prepends() {
        // Literal IP — bypasses DNS, parsed directly. We add a TEST-NET-3
        // (RFC 5737) address that's guaranteed unroutable so this test
        // doesn't accidentally rely on the network.
        let extras = vec!["192.0.2.7:39333".to_string()];
        let addrs = resolve_seeds_with(Network::Signet, None, &extras).await;
        assert!(!addrs.is_empty());
        match &addrs[0] {
            PeerAddr::Socket(sa) => {
                assert_eq!(sa.to_string(), "192.0.2.7:39333");
            }
            _ => panic!("expected first seed to be the operator-supplied literal IP"),
        }
    }

    #[tokio::test]
    async fn extra_signet_seeds_default_port_when_missing() {
        // Bare host (no `:port`) inherits signet's default P2P port.
        let extras = vec!["192.0.2.42".to_string()];
        let addrs = resolve_seeds_with(Network::Signet, None, &extras).await;
        match &addrs[0] {
            PeerAddr::Socket(sa) => {
                assert_eq!(sa.port(), 38333);
            }
            _ => panic!("expected literal IP entry"),
        }
    }

    #[tokio::test]
    async fn extra_signet_seeds_onion_routes_as_onion() {
        // A `.onion` host stays an Onion variant so the proxy routes
        // it correctly. The proxy is set so the built-in onion seeds
        // also come through.
        let extras = vec!["abcd1234.onion:38333".to_string()];
        let addrs = resolve_seeds_with(Network::Signet, Some("127.0.0.1:9050"), &extras).await;
        match &addrs[0] {
            PeerAddr::Onion { host, port } => {
                assert_eq!(host, "abcd1234.onion");
                assert_eq!(*port, 38333);
            }
            _ => panic!("expected first seed to be an Onion variant"),
        }
    }
}
