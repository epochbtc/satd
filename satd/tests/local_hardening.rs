//! What satd writes to its log when trace logging is on.
//!
//! Bitcoin Core logs neither RPC credentials nor RPC parameters at any log
//! level. satd's RPC server is jsonrpsee, whose TRACE output prints each HTTP
//! request with its headers (the `Authorization` header included) and each
//! call's parameters, so `-loglevel=trace` must not let that output through.

mod common;

use base64::Engine as _;
use common::TestNode;
use serde_json::json;

#[test]
fn trace_logging_never_writes_rpc_credentials_or_parameters() {
    let user = "traceloguser";
    let pass = "TraceLogPasswordMarker";
    let param = "TraceLogParamMarker";
    let user_arg = format!("--rpcuser={user}");
    let pass_arg = format!("--rpcpassword={pass}");
    let mut node = TestNode::start(&["--loglevel=trace", &user_arg, &pass_arg]);
    // The harness's RPC calls authenticate with `cookie` as `user:pass`.
    node.cookie = format!("{user}:{pass}");

    node.rpc_ok("getblockcount", vec![]);
    node.rpc_ok("echo", vec![json!(param)]);
    node.stop();

    let log = std::fs::read_to_string(&node.stderr_log).expect("read the node's log");
    // jsonrpsee's own DEBUG lines must still be in the log, or the absence
    // checks below could pass because its output was off altogether. (Before
    // the TRACE cap, these same arguments put every request's headers in the
    // log.)
    assert!(
        log.contains("Accepting new connection"),
        "jsonrpsee-server's debug output is missing; only its TRACE output should be left out"
    );

    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    for (what, secret) in [
        ("the Basic credential", basic.as_str()),
        ("the password", pass),
        ("an RPC parameter", param),
    ] {
        assert!(
            !log.contains(secret),
            "the trace log contains {what} ({secret}): {}",
            log.lines()
                .filter(|l| l.contains(secret))
                .take(3)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
