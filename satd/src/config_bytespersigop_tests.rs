//! `-bytespersigop`, from the command line or `bitcoin.conf`.

use super::*;

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

#[test]
fn the_option_reaches_the_config_from_either_source() {
    assert_eq!(load("", &[]).unwrap().bytespersigop, 20, "Core's default");
    assert_eq!(load("bytespersigop=30\n", &[]).unwrap().bytespersigop, 30);
    assert_eq!(load("", &["-bytespersigop=0"]).unwrap().bytespersigop, 0);
    assert_eq!(load("bytespersigop=30\n", &["-bytespersigop=40"]).unwrap().bytespersigop, 40, "the command line wins");
    for bad in ["bytespersigop=-1\n", "bytespersigop=lots\n"] {
        assert!(load(bad, &[]).is_err(), "{bad}");
    }
}
