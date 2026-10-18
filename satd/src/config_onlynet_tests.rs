//! `-onlynet`, `-proxy=0` / `-onion=0`, and `-proxy` soft-setting
//! `-listen=0`, as Core's `InitParameterInteraction` and `AppInitMain`
//! (`src/init.cpp`) resolve them.

use super::*;
use node::net::reachable::ReachableNets;

fn load(body: &str, extra: &[&str]) -> Result<Config, String> {
    let dir = tempfile::TempDir::new().unwrap();
    let conf = dir.path().join("bitcoin.conf");
    std::fs::write(&conf, body).unwrap();
    let mut args = vec![
        "satd",
        "--regtest",
        "--datadir",
        dir.path().to_str().unwrap(),
        "--conf",
        conf.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let args = normalize_args(args.into_iter().map(String::from).collect());
    Config::from_cli(CliArgs::try_parse_from(args).unwrap())
}

const NO_TOR: &str = "Outbound connections restricted to Tor (-onlynet=onion) but the proxy for reaching the \
                      Tor network is not provided: none of -proxy, -onion or -listenonion is given";

#[test]
fn without_onlynet_every_network_satd_can_reach_is_reachable() {
    let c = load("", &[]).unwrap();
    assert_eq!(c.reachable, ReachableNets { onion: false, ..ReachableNets::default() }, "no Tor proxy, no onion");
    assert!(c.dnsseed);
    let c = load("proxy=127.0.0.1:9050\n", &[]).unwrap();
    assert!(c.reachable.ipv4 && c.reachable.ipv6 && c.reachable.onion);
}

#[test]
fn onlynet_restricts_to_the_networks_it_names() {
    let c = load("onlynet=ipv4\n", &[]).unwrap();
    assert!(c.reachable.ipv4 && !c.reachable.ipv6 && !c.reachable.onion);
    assert!(c.dnsseed, "IPv4 is clearnet, so DNS seeding stays on");
    let c = load("onlynet=IPv6\nonlynet=ipv4\n", &[]).unwrap();
    assert!(c.reachable.ipv4 && c.reachable.ipv6);
}

/// The case that leaked: `onlynet=onion` with no way to reach Tor dialled
/// clearnet from the operator's address. Core refuses to start.
#[test]
fn onlynet_onion_without_a_tor_proxy_is_refused() {
    assert_eq!(load("onlynet=onion\n", &[]).err().as_deref(), Some(NO_TOR));
    assert!(load("onlynet=onion\nproxy=0\n", &[]).is_err(), "-proxy=0 is no proxy");
    assert_eq!(
        load("onlynet=onion\nproxy=127.0.0.1:9050\nonion=0\n", &[]).err().as_deref(),
        Some(
            "Outbound connections restricted to Tor (-onlynet=onion) but the proxy for reaching the Tor network \
             is explicitly forbidden: -onion=0"
        )
    );
    // A proxy for Tor is enough.
    assert!(load("onlynet=onion\nproxy=127.0.0.1:9050\n", &[]).is_ok());
    assert!(load("onlynet=onion\nonion=127.0.0.1:9050\n", &[]).is_ok());
    // Core also accepts -listenonion alone, taking Tor's SOCKS port from the
    // control connection later. satd cannot, so it refuses rather than start
    // with no outbound transport. Perturbation: drop that check and this
    // loads.
    let err = load("onlynet=onion\nlistenonion=1\n", &[]).expect_err("no outbound transport");
    assert!(err.contains("satd does not take the proxy from the Tor control port"), "{err}");
}

/// `-onion=0` keeps `.onion` out of reach even with `-proxy` (Core has no
/// `NET_ONION` proxy then), and is carried to the dialer.
#[test]
fn onion_zero_makes_onion_unreachable_whatever_the_proxy() {
    let c = load("proxy=127.0.0.1:9050\nonion=0\n", &[]).unwrap();
    assert!(c.noonion);
    assert!(!c.reachable.onion);
    assert_eq!(c.onion, None);
    let c = load("proxy=127.0.0.1:9050\n", &[]).unwrap();
    assert!(!c.noonion && c.reachable.onion);
}

#[test]
fn onlynet_without_clearnet_turns_dns_seeding_off_and_refuses_it_explicitly() {
    let c = load("onlynet=onion\nproxy=127.0.0.1:9050\n", &[]).unwrap();
    assert!(!c.dnsseed, "soft-set off");
    assert!(c.reachable.onion && !c.reachable.clearnet());
    assert_eq!(
        load("onlynet=onion\nproxy=127.0.0.1:9050\ndnsseed=1\n", &[]).err().as_deref(),
        Some("Incompatible options: -dnsseed=1 was explicitly specified, but -onlynet forbids connections to IPv4/IPv6")
    );
    assert!(!load("onlynet=onion\nproxy=127.0.0.1:9050\ndnsseed=0\n", &[]).unwrap().dnsseed);
}

#[test]
fn networks_satd_cannot_use_are_refused_as_core_refuses_them() {
    assert_eq!(
        load("onlynet=tor\n", &[]).err().as_deref(),
        Some("Unknown network specified in -onlynet: 'tor'")
    );
    assert_eq!(
        load("onlynet=i2p\n", &[]).err().as_deref(),
        Some("Outbound connections restricted to i2p (-onlynet=i2p) but -i2psam is not provided")
    );
    assert_eq!(
        load("onlynet=cjdns\n", &[]).err().as_deref(),
        Some("Outbound connections restricted to CJDNS (-onlynet=cjdns) but -cjdnsreachable is not provided")
    );
    let c = load("onlynet=cjdns\nonlynet=ipv6\ncjdnsreachable=1\n", &[]).unwrap();
    assert!(c.reachable.cjdns && c.reachable.ipv6 && c.reachable.cjdns_flip);
}

/// "To protect privacy, do not listen by default if a default proxy server
/// is specified." An explicit `-listen` or a `-bind` still wins, and
/// `-listen=0` carries `-listenonion=0` with it unless that is explicit too.
#[test]
fn a_proxy_turns_listening_off_by_default() {
    assert!(load("", &[]).unwrap().listen);
    let c = load("proxy=127.0.0.1:9050\n", &[]).unwrap();
    assert!(!c.listen);
    assert!(load("proxy=127.0.0.1:9050\nlisten=1\n", &[]).unwrap().listen);
    assert!(load("proxy=127.0.0.1:9050\nbind=127.0.0.1:18444\n", &[]).unwrap().listen);
    assert!(load("proxy=0\n", &[]).unwrap().listen, "-proxy=0 is no proxy");
    assert_eq!(load("proxy=0\n", &[]).unwrap().proxy, None);
    let c = load("proxy=127.0.0.1:9050\ntorcontrol=127.0.0.1:9051\n", &[]).unwrap();
    assert!(!c.listen && !c.listenonion, "-listen=0 soft-sets -listenonion=0");
    let c = load("proxy=127.0.0.1:9050\ntorcontrol=127.0.0.1:9051\nlistenonion=1\n", &[]).unwrap();
    assert!(!c.listen && c.listenonion, "an explicit -listenonion stands");
}
