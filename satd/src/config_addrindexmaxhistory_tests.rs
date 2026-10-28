//! `-addrindexmaxhistory`, the history cap the Electrum and Esplora
//! surfaces enforce.

use super::*;

fn load(body: &str, extra: &[&str]) -> Config {
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
    Config::from_cli(parse_cli(args).unwrap()).unwrap()
}

#[test]
fn the_default_cap_is_the_index_default() {
    let c = load("", &[]);
    assert_eq!(c.addrindexmaxhistory, node_index::DEFAULT_MAX_HISTORY_ENTRIES);
    assert_eq!(c.address_history_cap(), node_index::DEFAULT_MAX_HISTORY_ENTRIES);
}

#[test]
fn the_cap_is_read_from_the_config_file_and_the_command_line() {
    assert_eq!(load("addrindexmaxhistory=500000\n", &[]).address_history_cap(), 500_000);
    assert_eq!(
        load("addrindexmaxhistory=500000\n", &["--addrindexmaxhistory=1000"]).address_history_cap(),
        1_000,
        "the command line wins over the config file"
    );
}

#[test]
fn zero_means_no_cap() {
    let c = load("", &["--addrindexmaxhistory=0"]);
    assert_eq!(c.address_history_cap(), usize::MAX);
}
