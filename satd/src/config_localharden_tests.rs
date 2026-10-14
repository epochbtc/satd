//! `bitcoin.conf` comment handling and secret-free `Debug` output.

use super::*;

/// Parse `body` as the `--conf` file of a regtest node with its datadir in
/// `dir`, plus `extra` command-line flags.
fn config_from(dir: &tempfile::TempDir, body: &str, extra: &[&str]) -> Result<Config, String> {
    let conf = dir.path().join("comments.conf");
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
    Config::from_cli(CliArgs::try_parse_from(args).unwrap())
}

fn global(cf: &ConfigFile, key: &str) -> Vec<String> {
    cf.global.get(key).cloned().unwrap_or_default()
}

/// Bitcoin Core's GetConfigOptions (src/common/config.cpp) drops everything
/// from the first `#` on a line, wherever it is, before it reads the line.
#[test]
fn an_inline_comment_is_not_part_of_the_value() {
    let cf = ConfigFile::parse(
        "txindex=1 # keep the transaction index\n\
         rpcport=8332\t# the RPC port\n\
         uacomment=abc#def\n\
         includeconf=extra.conf # more settings\n\
         # a whole-line comment\n\
         \x20  # an indented comment\n\
         [test]  # the testnet3 section\n\
         rpcport=18332 #x\n",
    )
    .unwrap();
    assert_eq!(global(&cf, "txindex"), ["1"]);
    assert_eq!(global(&cf, "rpcport"), ["8332"]);
    assert_eq!(global(&cf, "uacomment"), ["abc"]);
    assert_eq!(global(&cf, "includeconf"), ["extra.conf"]);
    assert_eq!(
        cf.sections.get("test").and_then(|s| s.get("rpcport")).cloned(),
        Some(vec!["18332".to_string()]),
        "a section header followed by a comment still opens the section"
    );
}

/// The values a node actually runs with: before, `rpcport=18555 # c` failed
/// to parse as a port and the default was used without a word.
#[test]
fn inline_comments_reach_the_running_config_as_core_reads_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_from(
        &dir,
        "rpcuser=alice # the operator\nrpcpassword=pw\n[regtest] # this chain\n\
         rpcport=18555 # not the default\n",
        &[],
    )
    .unwrap();
    assert_eq!(cfg.rpcport, 18555);
    assert_eq!(cfg.rpcuser.as_deref(), Some("alice"));
}

/// Core refuses an `rpcpassword` line that holds a `#` at all, rather than
/// guess whether it starts a comment or belongs to the password
/// (src/common/config.cpp GetConfigOptions; the caller adds the
/// "Error reading configuration file: " prefix, src/common/init.cpp).
#[test]
fn a_hash_on_an_rpcpassword_line_is_refused_with_cores_message() {
    let cases = [
        ("rpcpassword=pw # old password\n", 1),
        ("rpcpassword=a#b\n", 1),
        ("server=1\n[regtest]\nrpcpassword=#\n", 3),
    ];
    for (body, line) in cases {
        let err = ConfigFile::parse(body).expect_err(body);
        assert_eq!(
            err,
            format!(
                "Error reading configuration file: parse error on line {line}, using # in \
                 rpcpassword can be ambiguous and should be avoided"
            ),
            "{body:?}"
        );
    }

    // satd reads a bare key as `key=1`, where Core refuses any line without
    // `=`; with a `#` on it, a bare `rpcpassword` is refused too.
    assert!(ConfigFile::parse("rpcpassword # no value\n").is_err());

    // A commented-out password line is only a comment, and a `#` on any
    // other key is a comment, as in Core.
    let cf = ConfigFile::parse("# rpcpassword=old\nrpcpassword=pw\nrpcuser=bob#x\n").unwrap();
    assert_eq!(global(&cf, "rpcpassword"), ["pw"]);
    assert_eq!(global(&cf, "rpcuser"), ["bob"]);

    // The running config refuses it the same way.
    let dir = tempfile::tempdir().expect("tempdir");
    let err = config_from(&dir, "rpcuser=u\nrpcpassword=pw # c\n", &[]).unwrap_err();
    assert!(err.contains("using # in rpcpassword"), "got: {err}");
}

/// Core trims only spaces, tabs, CRs and LFs around a line, a key and a value
/// (`TrimString(str, " \t\r\n")`), so a vertical tab or a form feed stays in
/// the value.
#[test]
fn whitespace_is_trimmed_as_core_trims_it() {
    let cf = ConfigFile::parse(" \t rpcuser \t=\t alice \t\r\nuacomment=x\u{b}\nrpcbind=\u{c}y\n").unwrap();
    assert_eq!(global(&cf, "rpcuser"), ["alice"]);
    assert_eq!(global(&cf, "uacomment"), ["x\u{b}"]);
    assert_eq!(global(&cf, "rpcbind"), ["\u{c}y"]);
}

/// `Config` holds the RPC, Tor, Esplora and webhook secrets. Its `Debug`
/// output must not, so a stray `{:?}` or a panic message cannot write them to
/// the log.
#[test]
fn config_debug_output_carries_no_secrets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_from(
        &dir,
        "",
        &[
            "--rpcuser=dbguser",
            "--rpcpassword=RpcPasswordMarker",
            "--rpcauth=authuser:0123456789abcdef$\
             9383f6d244049af54e59a84188e2f2b1e58ff20de019156bc0c430ff8ae4c7a3",
            "--torpassword=TorPasswordMarker",
            "--esplorauserpass=esplora:EsploraPasswordMarker",
            "--reorg-webhook=http://127.0.0.1:9/hook",
            "--reorg-webhook-secret=WebhookSecretMarker",
        ],
    )
    .unwrap();
    assert_eq!(cfg.rpcpassword.as_deref(), Some("RpcPasswordMarker"));
    let shown = format!("{cfg:?}");
    for secret in [
        "RpcPasswordMarker",
        "TorPasswordMarker",
        "EsploraPasswordMarker",
        "WebhookSecretMarker",
        "9383f6d2",
    ] {
        assert!(!shown.contains(secret), "Config Debug shows {secret}: {shown}");
    }
    let shown_alt = format!("{cfg:#?}");
    assert!(!shown_alt.contains("RpcPasswordMarker"), "{shown_alt}");
    assert!(shown.contains("Regtest"), "Config Debug still names the network: {shown}");

    let entry = &cfg.rpcauth[0];
    let shown = format!("{entry:?}");
    assert!(shown.contains("authuser"), "{shown}");
    assert!(!shown.contains(&format!("{:?}", entry.hash)), "rpcauth hash shown: {shown}");

    let hook = crate::reload::webhook_target_from(&cfg).unwrap();
    let shown = format!("{hook:?}");
    assert!(shown.contains("127.0.0.1:9/hook"), "{shown}");
    assert!(!shown.contains("WebhookSecretMarker"), "webhook secret shown: {shown}");
}

/// A callsite for metadata built by hand: the filters only read the metadata
/// they are handed, never the callsite's.
struct TestCallsite;

impl tracing::callsite::Callsite for TestCallsite {
    fn set_interest(&self, _: tracing::subscriber::Interest) {}
    fn metadata(&self) -> &tracing::Metadata<'_> {
        unreachable!("filters read the metadata they are handed")
    }
}

static TEST_CALLSITE: TestCallsite = TestCallsite;

/// Whether satd's log stack, with `filter` as its reloadable filter and
/// [`request_dump_guard`] beside it as `main` installs them, writes an event
/// at `level` from `target`. The subscriber is asked directly, so no global
/// dispatcher or callsite cache is involved.
fn would_log(filter: tracing_subscriber::EnvFilter, target: &str, level: tracing::Level) -> bool {
    use tracing::Subscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    let meta = tracing::Metadata::new(
        "event",
        target,
        level,
        None,
        None,
        None,
        tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(&TEST_CALLSITE)),
        tracing::metadata::Kind::EVENT,
    );
    tracing_subscriber::registry()
        .with(filter)
        .with(request_dump_guard())
        .enabled(&meta)
}

/// jsonrpsee's TRACE output prints the HTTP `Authorization` header and the
/// call parameters; tungstenite's prints WebSocket payloads. Trace logging
/// must not turn either on, while their DEBUG output and satd's own TRACE
/// output still get through.
#[test]
fn trace_logging_leaves_out_the_request_dumps() {
    use tracing::Level;
    let dumps = [
        "jsonrpsee-server",
        "jsonrpsee_server::server",
        "jsonrpsee-core",
        "jsonrpsee_core::server::rpc_module",
        "jsonrpsee",
        "tungstenite::protocol::frame",
    ];

    let cfg = Config::from_cli(
        CliArgs::try_parse_from(["satd", "--regtest", "--loglevel=trace"]).unwrap(),
    )
    .unwrap();
    for target in dumps {
        assert!(
            !would_log(build_env_filter(&cfg), target, Level::TRACE),
            "{target} TRACE is logged under -loglevel=trace"
        );
        assert!(
            would_log(build_env_filter(&cfg), target, Level::DEBUG),
            "{target} DEBUG must still be logged under -loglevel=trace"
        );
    }
    assert!(would_log(build_env_filter(&cfg), "node::rpc::server", Level::TRACE));

    // Directives naming the targets, more specifically than the guard's
    // prefixes, cannot turn them back on.
    let explicit = "trace,jsonrpsee-server=trace,jsonrpsee_core::server::rpc_module=trace,\
                    tungstenite::protocol=trace";
    for target in dumps {
        assert!(
            !would_log(tracing_subscriber::EnvFilter::new(explicit), target, Level::TRACE),
            "{target} TRACE is logged when a directive names it"
        );
    }
    assert!(would_log(tracing_subscriber::EnvFilter::new(explicit), "node::net", Level::TRACE));
}
