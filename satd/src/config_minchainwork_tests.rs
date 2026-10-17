//! `-minimumchainwork`, as Core's `uint256::FromUserHex` reads it.

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

fn work(low: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[32 - low.len()..].copy_from_slice(low);
    w
}

#[test]
fn values_are_left_padded_hex_with_an_optional_prefix() {
    assert_eq!(parse_minimum_chain_work("0xffff"), Ok(work(&[0xff, 0xff])));
    assert_eq!(parse_minimum_chain_work("ffff"), Ok(work(&[0xff, 0xff])));
    assert_eq!(parse_minimum_chain_work("1"), Ok(work(&[0x01])), "an odd digit count is padded");
    assert_eq!(parse_minimum_chain_work("0x"), Ok([0u8; 32]), "Core reads an empty value as zero");
    assert_eq!(parse_minimum_chain_work(&"f".repeat(64)), Ok([0xff; 32]));
}

#[test]
fn values_core_refuses_are_refused_with_its_message() {
    for bad in ["0xzz", "12 34", "-1", &"0".repeat(65)] {
        let err = parse_minimum_chain_work(bad).expect_err(bad);
        assert_eq!(err, format!("Invalid minimum work specified ({bad}), must be up to 64 hex digits"));
    }
}

#[test]
fn the_option_reaches_the_config_from_either_source() {
    assert_eq!(load("", &[]).unwrap().minimumchainwork, None);
    assert_eq!(load("minimumchainwork=0xffff\n", &[]).unwrap().minimumchainwork, Some(work(&[0xff, 0xff])));
    assert_eq!(load("", &["-minimumchainwork=0x10"]).unwrap().minimumchainwork, Some(work(&[0x10])));
    assert!(load("minimumchainwork=nothex\n", &[]).is_err());
}
