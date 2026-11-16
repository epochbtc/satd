//! End to end: the request `sat-cli` puts on the wire for a raw RPC call,
//! read by a one-shot HTTP sink. Expectations are what `bitcoin-cli` v32.1
//! sent for the same command line (#1268).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

struct Captured {
    body: serde_json::Value,
    auth: String,
}

/// Run `sat-cli` with `args` (and `stdin`) against a sink that answers one
/// request with a null result, and return the request it received.
fn capture(args: &[&str], stdin: &str) -> Captured {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let sink = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut len = 0;
        let mut auth = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            let (k, v) = line.split_once(':').unwrap_or((line, ""));
            match k.to_ascii_lowercase().as_str() {
                "content-length" => len = v.trim().parse().unwrap(),
                "authorization" => auth = v.trim().to_string(),
                _ => {}
            }
        }
        let mut body = vec![0; len];
        reader.read_exact(&mut body).unwrap();
        let reply = r#"{"jsonrpc":"2.0","result":null,"id":"sat-cli"}"#;
        write!(
            reader.get_mut(),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        )
        .unwrap();
        Captured {
            body: serde_json::from_slice(&body).unwrap(),
            auth,
        }
    });

    let datadir =
        std::env::temp_dir().join(format!("sat-cli-convert-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&datadir).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_sat-cli"))
        .arg("-regtest")
        .arg(format!("-datadir={}", datadir.display()))
        .arg(format!("-rpcport={port}"))
        .arg("-rpcuser=u")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let _ = std::fs::remove_dir_all(&datadir);
    assert!(out.status.success(), "sat-cli failed: {}", String::from_utf8_lossy(&out.stderr));
    sink.join().unwrap()
}

fn params(args: &[&str]) -> serde_json::Value {
    let mut all = vec!["-rpcpassword=p"];
    all.extend_from_slice(args);
    capture(&all, "").body["params"].clone()
}

#[test]
fn positional_arguments_convert_as_bitcoin_cli_does() {
    assert_eq!(
        params(&["signmessagewithprivkey", "cVpF924E", "123"]),
        serde_json::json!(["cVpF924E", "123"])
    );
    assert_eq!(params(&["decodescript", "5151"]), serde_json::json!(["5151"]));
    assert_eq!(params(&["getblock", "00ab", "2"]), serde_json::json!(["00ab", 2]));
}

#[test]
fn named_arguments_convert_as_bitcoin_cli_does() {
    assert_eq!(
        params(&["-named", "getnewaddress", "label=123"]),
        serde_json::json!({"label": "123"})
    );
    assert_eq!(
        params(&["-named", "getblock", "00ab", "verbosity=2"]),
        serde_json::json!({"verbosity": 2, "args": ["00ab"]})
    );
}

#[test]
fn a_listed_argument_that_is_not_json_is_refused() {
    // Refused before any connection: nothing listens on port 1.
    let datadir =
        std::env::temp_dir().join(format!("sat-cli-convert-{}-refused", std::process::id()));
    std::fs::create_dir_all(&datadir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sat-cli"))
        .args(["-regtest", "-rpcport=1", "-rpcuser=u", "-rpcpassword=p"])
        .arg(format!("-datadir={}", datadir.display()))
        .args(["getblockheader", "ab", "notabool"])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&datadir);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "error: Error parsing JSON: notabool");
}

#[test]
fn stdin_lines_are_arguments_and_stdinrpcpass_takes_the_first() {
    // Core keeps an empty line as an empty argument, and a line that looks
    // like a flag is still an argument.
    let c = capture(&["-rpcpassword=p", "-stdin", "echo"], "line1\n\n123\n-5\n");
    assert_eq!(c.body["params"], serde_json::json!(["line1", "", "123", "-5"]));

    // The method itself may come from stdin, after the password.
    let c = capture(&["-rpcpassword=other", "-stdinrpcpass", "-stdin"], "pw\ngetblock\n00ab\n2\n");
    assert_eq!(c.body["method"], "getblock");
    assert_eq!(c.body["params"], serde_json::json!(["00ab", 2]));

    // Basic base64("u:pw"): the stdin password replaces -rpcpassword.
    assert_eq!(c.auth, "Basic dTpwdw==");

    // A stdin line that looks like an option is still an argument, the
    // method included.
    let c = capture(&["-rpcpassword=p", "-stdin"], "--named\ngetblockcount\n");
    assert_eq!(c.body["method"], "--named");
    assert_eq!(c.body["params"], serde_json::json!(["getblockcount"]));
    let c = capture(&["-rpcpassword=p", "-stdin", "echo"], "--help\n--rpcuser=x\n");
    assert_eq!(c.body["params"], serde_json::json!(["--help", "--rpcuser=x"]));
}
