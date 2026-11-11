//! The live node of the spec's interop suite (PROTOCOL.md section 5): a
//! real `satd -consensus=rust` that syncs from one Bitcoin Core node over
//! P2P, stops at the block the runner names, and reports its UTXO set hash.
//!
//! ```sh
//! bcs-conformance interop --bitcoind <bitcoind> --node "satd-conformance-harness --interop-node \
//!   --satd <satd> --network {network} --datadir {datadir} --peer {peer} --stop-at {stop_at} --options {options}"
//! ```
//!
//! Everything consensus-relevant is satd's own: the network options become
//! satd's command-line flags, and an option satd has no flag for ends the
//! run with an error rather than being dropped. satd's `gettxoutsetinfo`
//! keeps no UTXO set hash (it refuses `hash_serialized_3`), so once satd has
//! stopped cleanly the hash is computed here over its own chainstate, with
//! the same hasher as the corpus's `utxo_hash`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use base64::Engine;
use bitcoin::BlockHash;
use serde_json::{json, Map, Value};

/// How long satd may go without moving its tip before the run fails.
const DEFAULT_STALL_SECS: u64 = 120;
/// How long a clean shutdown may take.
const STOP_TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(250);

struct Args {
    satd: PathBuf,
    network: String,
    datadir: PathBuf,
    peer: String,
    stop_at: BlockHash,
    options: Map<String, Value>,
    stall: Duration,
}

/// Runs the node and exits the process: status 0 after the `stopped` line,
/// 1 after an `error` line.
pub fn main(args: &[String]) -> ! {
    let outcome = parse(args).and_then(|args| run(&args));
    match outcome {
        Ok(stopped) => {
            println!("{stopped}");
            std::process::exit(0);
        }
        Err(error) => {
            println!("{}", error.line());
            std::process::exit(1);
        }
    }
}

/// Why the node could not reach `{stop_at}`, with the tip it had.
struct Error {
    message: String,
    tip: Option<(String, u64)>,
}

impl Error {
    fn line(&self) -> Value {
        let mut line = json!({"event": "error", "message": self.message});
        if let Some((tip, height)) = &self.tip {
            line["tip"] = json!(tip);
            line["height"] = json!(height);
        }
        line
    }
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Error { message, tip: None }
    }
}

fn parse(args: &[String]) -> Result<Args, Error> {
    let mut satd = None;
    let mut network = None;
    let mut datadir = None;
    let mut peer = None;
    let mut stop_at = None;
    let mut options = Map::new();
    let mut stall = Duration::from_secs(DEFAULT_STALL_SECS);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--satd" => satd = Some(PathBuf::from(value)),
            "--network" => network = Some(value.clone()),
            "--datadir" => datadir = Some(PathBuf::from(value)),
            "--peer" => peer = Some(value.clone()),
            "--stop-at" => {
                stop_at = Some(BlockHash::from_str(value).map_err(|e| format!("--stop-at: {e}"))?)
            }
            "--options" => match serde_json::from_str(value) {
                Ok(Value::Object(o)) => options = o,
                _ => return Err(format!("--options must be a JSON object, got {value}").into()),
            },
            "--stall-timeout" => {
                stall = Duration::from_secs(value.parse().map_err(|_| format!("--stall-timeout: {value}"))?)
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    Ok(Args {
        satd: satd.ok_or("--satd is required".to_string())?,
        network: network.ok_or("--network is required".to_string())?,
        datadir: datadir.ok_or("--datadir is required".to_string())?,
        peer: peer.ok_or("--peer is required".to_string())?,
        stop_at: stop_at.ok_or("--stop-at is required".to_string())?,
        options,
        stall,
    })
}

/// satd's network flag and the subdirectory of the data directory it keeps
/// that network's chainstate in.
fn network(name: &str) -> Result<(Option<&'static str>, Option<&'static str>), String> {
    Ok(match name {
        "main" => (None, None),
        "testnet3" => (Some("-testnet"), Some("testnet3")),
        "testnet4" => (Some("-testnet4"), Some("testnet4")),
        "signet" => (Some("-signet"), Some("signet")),
        "regtest" => (Some("-regtest"), Some("regtest")),
        other => return Err(format!("unknown network {other}")),
    })
}

/// satd's flags for the network options of PROTOCOL.md section 4.8. An
/// option satd has no flag for is an error: the node would otherwise run
/// under different consensus parameters from Core's.
fn option_flags(options: &Map<String, Value>) -> Result<Vec<String>, String> {
    let mut flags = Vec::new();
    for (key, value) in options {
        match key.as_str() {
            "testactivationheight" => {
                let map = value.as_object().ok_or("testactivationheight must be an object")?;
                for (name, height) in map {
                    let height = height.as_u64().ok_or(format!("testactivationheight {name} is not a height"))?;
                    flags.push(format!("-testactivationheight={name}@{height}"));
                }
            }
            "test" => {
                let names = value.as_array().ok_or("test must be an array")?;
                if let Some(name) = names.first() {
                    return Err(format!("satd has no -test={} option", name.as_str().unwrap_or("?")));
                }
            }
            "signetchallenge" => {
                let challenge = value.as_str().ok_or("signetchallenge must be a hex string")?;
                flags.push(format!("-signetchallenge={challenge}"));
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(flags)
}

fn run(args: &Args) -> Result<Value, Error> {
    let (network_flag, subdir) = network(&args.network)?;
    let mut flags: Vec<String> = network_flag.into_iter().map(String::from).collect();
    flags.extend(option_flags(&args.options)?);
    let rpc_port = free_port()?;
    flags.extend([
        format!("-datadir={}", args.datadir.display()),
        format!("-connect={}", args.peer),
        // The version 1 transport (PROTOCOL.md section 5, rule 1).
        "-v2transport=0".into(),
        "-listen=0".into(),
        "-consensus=rust".into(),
        format!("-rpcport={rpc_port}"),
        "-rpcbind=127.0.0.1".into(),
        "-rpcallowip=127.0.0.1".into(),
    ]);
    let net_dir = match subdir {
        Some(sub) => args.datadir.join(sub),
        None => args.datadir.clone(),
    };

    // satd's standard output goes to standard error: only the protocol's
    // lines may appear on ours.
    let stderr = std::io::stderr().as_fd().try_clone_to_owned().map_err(|e| format!("duplicating stderr: {e}"))?;
    let child = Command::new(&args.satd)
        .args(&flags)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stderr))
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("starting {}: {e}", args.satd.display()))?;
    let mut node = Node { child: Some(child), rpc_port, cookie: net_dir.join(".cookie") };

    let stop_at = args.stop_at.to_string();
    let height = node.sync_to(&stop_at, args.stall)?;
    node.stop().map_err(|message| Error { message, tip: Some((stop_at.clone(), height)) })?;

    let (tip, hash) = utxo_hash(&net_dir)?;
    if tip != args.stop_at {
        return Err(Error {
            message: format!("satd's chainstate is at {tip} after stopping, not {stop_at}"),
            tip: Some((stop_at, height)),
        });
    }
    Ok(json!({"event": "stopped", "tip": stop_at, "height": height, "hash_serialized_3": hash}))
}

/// A port nothing listens on, for satd's RPC.
fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("finding a free port: {e}"))?;
    listener.local_addr().map(|a| a.port()).map_err(|e| format!("finding a free port: {e}"))
}

struct Node {
    /// `None` once satd has exited.
    child: Option<Child>,
    rpc_port: u16,
    cookie: PathBuf,
}

impl Node {
    /// Waits until satd's active tip is `stop_at` and returns its height.
    /// Fails when satd exits, marks a block invalid, or keeps the same tip
    /// for `stall`.
    fn sync_to(&mut self, stop_at: &str, stall: Duration) -> Result<u64, Error> {
        let mut last: Option<(String, u64)> = None;
        let mut changed = Instant::now();
        loop {
            if let Some(status) = self.exited() {
                return Err(Error { message: format!("satd exited ({status})"), tip: last });
            }
            // Errors while satd starts (no cookie yet, RPC warming up) are
            // waited out; the stall timer bounds them.
            if let Ok(tip) = self.call("getbestblockhash", json!([])) {
                let tip = tip.as_str().unwrap_or_default().to_string();
                if last.as_ref().map(|(t, _)| t) != Some(&tip) {
                    let height = self.call("getblockcount", json!([]))?.as_u64().unwrap_or_default();
                    println!("{}", json!({"event": "tip", "tip": tip, "height": height}));
                    last = Some((tip.clone(), height));
                    changed = Instant::now();
                }
                if tip == stop_at {
                    return Ok(last.map(|(_, h)| h).unwrap_or_default());
                }
                if let Some(invalid) = self.invalid_tip()? {
                    return Err(Error { message: format!("satd marked block {invalid} invalid"), tip: last });
                }
            }
            if changed.elapsed() >= stall {
                return Err(Error {
                    message: format!("no new tip for {} s", stall.as_secs()),
                    tip: last,
                });
            }
            std::thread::sleep(POLL);
        }
    }

    /// A chain tip satd holds as invalid. The peer is a Core node that only
    /// serves blocks it accepted, so any such tip is a disagreement.
    fn invalid_tip(&mut self) -> Result<Option<String>, Error> {
        let tips = self.call("getchaintips", json!([]))?;
        Ok(tips.as_array().into_iter().flatten().find_map(|t| {
            (t.get("status").and_then(Value::as_str) == Some("invalid"))
                .then(|| t.get("hash").and_then(Value::as_str).unwrap_or("?").to_string())
        }))
    }

    /// Asks satd to stop and waits for it to exit cleanly.
    fn stop(&mut self) -> Result<(), String> {
        self.call("stop", json!([])).map_err(|e| format!("stopping satd: {}", e.message))?;
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            if let Some(status) = self.exited() {
                return if status.success() { Ok(()) } else { Err(format!("satd stopped with {status}")) };
            }
            if Instant::now() >= deadline {
                return Err(format!("satd did not stop within {} s", STOP_TIMEOUT.as_secs()));
            }
            std::thread::sleep(POLL);
        }
    }

    fn exited(&mut self) -> Option<ExitStatus> {
        let status = self.child.as_mut()?.try_wait().ok()??;
        self.child = None;
        Some(status)
    }

    /// One JSON-RPC call over HTTP/1.1, authenticated with satd's cookie.
    fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        rpc(self.rpc_port, &self.cookie, method, params).map_err(Error::from)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn rpc(port: u16, cookie: &Path, method: &str, params: Value) -> Result<Value, String> {
    let credentials = std::fs::read_to_string(cookie).map_err(|e| format!("reading {}: {e}", cookie.display()))?;
    let auth = base64::engine::general_purpose::STANDARD.encode(credentials.trim());
    let body = json!({"jsonrpc": "1.0", "id": 0, "method": method, "params": params}).to_string();
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connecting to satd's RPC: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(60))).map_err(|e| e.to_string())?;
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {auth}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(|e| format!("{method}: {e}"))?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(|e| format!("{method}: {e}"))?;
    let response = String::from_utf8_lossy(&response);
    let (head, body) = response.split_once("\r\n\r\n").ok_or(format!("{method}: no HTTP body"))?;
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        dechunk(body).ok_or(format!("{method}: bad chunked body"))?
    } else {
        body.to_string()
    };
    let reply: Value = serde_json::from_str(&body).map_err(|e| format!("{method}: {e}: {head}"))?;
    match reply.get("error") {
        Some(Value::Null) | None => Ok(reply.get("result").cloned().unwrap_or(Value::Null)),
        Some(error) => Err(format!("{method}: {error}")),
    }
}

fn dechunk(mut body: &str) -> Option<String> {
    let mut out = String::new();
    loop {
        let (size, rest) = body.split_once("\r\n")?;
        let size = usize::from_str_radix(size.trim(), 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        out.push_str(rest.get(..size)?);
        body = rest.get(size + 2..)?;
    }
}

/// The tip and `hash_serialized_3` of the chainstate satd left in `net_dir`.
fn utxo_hash(net_dir: &Path) -> Result<(BlockHash, String), String> {
    use node::storage::Store;
    let store = node::storage::rocksdb_store::RocksDbStore::open(net_dir, false, 16, false, 256)
        .map_err(|e| format!("opening satd's chainstate: {e}"))?;
    let tip = store.get_tip().ok_or("satd's chainstate has no tip")?;
    let mut hasher = node::storage::compressed_coin::Hs3Hasher::new();
    store
        .for_each_coin_snapshot(&mut |op, coin| {
            hasher.visit(op, coin);
            Ok(())
        })
        .map_err(|e| format!("reading satd's UTXO set: {e}"))?;
    Ok((tip, hex::encode(hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn activation_heights_become_satd_flags() {
        let mut flags = option_flags(&options(json!({"testactivationheight": {"segwit": 432, "bip34": 2}}))).unwrap();
        flags.sort();
        assert_eq!(flags, ["-testactivationheight=bip34@2", "-testactivationheight=segwit@432"]);
        assert_eq!(option_flags(&Map::new()).unwrap(), Vec::<String>::new());
        assert_eq!(option_flags(&options(json!({"test": []}))).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn an_option_satd_lacks_is_an_error() {
        let err = option_flags(&options(json!({"test": ["bip94"]}))).unwrap_err();
        assert_eq!(err, "satd has no -test=bip94 option");
        assert!(option_flags(&options(json!({"other": 1}))).is_err());
    }

    #[test]
    fn chunked_bodies_are_joined() {
        assert_eq!(dechunk("4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n").as_deref(), Some("{\"a\":1}"));
        assert_eq!(dechunk("z\r\n"), None);
    }
}
