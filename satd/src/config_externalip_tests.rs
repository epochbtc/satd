//! `-externalip`, including a v3 onion address (#973).

use super::*;

#[inline(never)]
fn load(extra: &[&str]) -> Result<Box<Config>, String> {
    let dir = tempfile::TempDir::new().unwrap();
    let conf = dir.path().join("bitcoin.conf");
    std::fs::write(&conf, "").unwrap();
    let mut args = vec!["satd", "--regtest", "--datadir", dir.path().to_str().unwrap(), "--conf", conf.to_str().unwrap()];
    args.extend_from_slice(extra);
    let args = normalize_args(args.into_iter().map(String::from).collect());
    let cli = Box::new(CliArgs::try_parse_from(args).unwrap());
    Config::from_cli(*cli).map(Box::new)
}

/// Core's manual hidden-service setup names the service with
/// `-externalip=<x>.onion`; satd refused that at startup.
#[test]
fn an_onion_externalip_is_accepted_with_or_without_a_port() {
    let host = node::net::peer::torv3_to_onion_host(&[7u8; 32]);
    let cfg = load(&[&format!("-externalip={host}"), &format!("-externalip={}:8333", host.to_uppercase()), "-externalip=1.2.3.4"]).unwrap();
    assert_eq!(cfg.externalip_onion, vec![(host.clone(), 18444), (host, 8333)]);
    assert_eq!(cfg.externalip, vec!["1.2.3.4:18444".parse().unwrap()]);
}

#[test]
fn a_malformed_onion_or_a_hostname_is_still_refused() {
    for bad in ["-externalip=notanonion.onion", "-externalip=example.com", "-externalip=abc.onion:port"] {
        assert!(load(&[bad]).is_err(), "{bad}");
    }
}
