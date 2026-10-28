//! List options from both the command line and `bitcoin.conf`, merged as
//! Core's `GetSettingsList` merges them (#995).

use super::*;

/// The config, boxed: `Config` and `CliArgs` are large enough that two on
/// the stack of a test thread overflow it (#1002).
#[inline(never)]
fn load(body: &str, extra: &[&str]) -> Box<Config> {
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
    let cli = Box::new(parse_cli(args).unwrap());
    Box::new(Config::from_cli(*cli).unwrap())
}

/// Core's `p2p_getaddr_caching.py`: its framework writes `bind=127.0.0.1` to
/// `bitcoin.conf`, and the test adds two onion binds on the command line.
/// Core listens on all three; satd listened only on the two onion binds.
#[test]
fn a_bind_on_the_command_line_adds_to_the_config_files() {
    let cfg = load(
        "[regtest]\nbind=127.0.0.1\n",
        &["-bind=127.0.0.1:28001=onion", "-bind=127.0.0.1:28002=onion"],
    );
    let binds: Vec<(String, bool)> = cfg.binds.iter().map(|b| (b.addr.to_string(), b.onion)).collect();
    assert_eq!(
        binds,
        vec![
            ("127.0.0.1:28001".to_string(), true),
            ("127.0.0.1:28002".to_string(), true),
            ("127.0.0.1:18444".to_string(), false),
        ],
        "command line first, then the config file"
    );
}

#[test]
fn addnode_seednode_and_onlynet_take_both_sources() {
    let cfg = load(
        "[regtest]\naddnode=10.0.0.1\nseednode=10.0.0.3\nonlynet=ipv4\n",
        &["-addnode=10.0.0.2", "-seednode=10.0.0.4", "-onlynet=ipv6"],
    );
    assert_eq!(cfg.addnode, ["10.0.0.2", "10.0.0.1"]);
    assert_eq!(cfg.seednode, ["10.0.0.4", "10.0.0.3"]);
    assert_eq!(cfg.onlynet, ["ipv6", "ipv4"]);
}

/// A command line that ends in `-noconnect` drops the config file's peers;
/// one that names a peer after the negation keeps them, as Core's
/// `GetSettingsList` keeps "zombie" config values.
#[test]
fn a_negated_connect_drops_the_config_files_peers_unless_a_peer_follows() {
    let file = "[regtest]\nconnect=10.0.0.1\n";

    let cfg = load(file, &["-connect=10.0.0.2"]);
    assert_eq!(cfg.connect, ["10.0.0.2", "10.0.0.1"]);
    assert!(!cfg.automatic_outbound);

    let cfg = load(file, &["-connect=10.0.0.2", "-noconnect"]);
    assert!(cfg.connect.is_empty(), "{:?}", cfg.connect);
    assert!(!cfg.automatic_outbound, "a negation still turns automatic outbound off");

    let cfg = load(file, &["-connect=10.0.0.2", "-noconnect", "-connect=10.0.0.3"]);
    assert_eq!(cfg.connect, ["10.0.0.3", "10.0.0.1"], "values before the negation go; the file's come back");

    let cfg = load("", &["-noconnect"]);
    assert!(cfg.connect.is_empty());
    assert!(!cfg.automatic_outbound);
}

#[test]
fn a_negated_rpcauth_drops_the_config_files_entries_unless_one_follows() {
    // Two `rpcauth` lines Core's `rpcauth.py` could have written.
    let a = "a:f7efda5c189b999524f151318c0c86$d5b51b3beffbc02b724e5d095828e0bc8b2456e9ac8757ae3211a5d9b16a22ae";
    let b = "b:f7efda5c189b999524f151318c0c86$d5b51b3beffbc02b724e5d095828e0bc8b2456e9ac8757ae3211a5d9b16a22ae";
    let file = format!("rpcauth={a}\n");
    let users = |cfg: &Config| cfg.rpcauth.iter().map(|e| e.username.clone()).collect::<Vec<_>>();

    assert_eq!(users(&load(&file, &[&format!("-rpcauth={b}")])), ["b", "a"]);
    assert!(users(&load(&file, &[&format!("-rpcauth={b}"), "-norpcauth"])).is_empty());
    assert_eq!(users(&load(&file, &["-norpcauth", &format!("-rpcauth={b}")])), ["b", "a"]);
}

#[test]
fn merge_list_follows_core_settings_list() {
    let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    const N: &str = "\u{0}neg";
    assert_eq!(merge_list(v(&["a"]), v(&["b"]), None), v(&["a", "b"]));
    assert_eq!(merge_list(v(&[]), v(&["b"]), None), v(&["b"]));
    assert_eq!(merge_list(v(&["a", N]), v(&["b"]), Some(N)), v(&[]));
    assert_eq!(merge_list(v(&["a", N, "c"]), v(&["b"]), Some(N)), v(&["c", "b"]));
    // The config file's own negation trims only the config file's values.
    assert_eq!(merge_list(v(&["a"]), v(&["b", N, "d"]), Some(N)), v(&["a", "d"]));
}
