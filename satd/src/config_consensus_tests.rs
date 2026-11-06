//! `-consensus`, from the command line or `bitcoin.conf`.

use super::*;

fn load(body: &str, extra: &[&str]) -> ConsensusEngine {
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
    Config::from_cli(parse_cli(args).unwrap()).unwrap().consensus
}

#[test]
fn the_default_engine_is_rust_primary_with_a_cpp_shadow() {
    assert_eq!(load("", &[]), ConsensusEngine::CppShadow);
    assert_eq!(load("consensus=bogus\n", &[]), ConsensusEngine::CppShadow, "an unknown name falls back to the default");
    assert_eq!(load("consensus=rust-shadow\n", &[]), ConsensusEngine::RustShadow);
    assert_eq!(load("consensus=rust-shadow\n", &["-consensus=cpp"]), ConsensusEngine::Cpp, "the command line wins");
    assert_eq!(load("", &["-consensus=rust"]), ConsensusEngine::Rust);
}
