//! The test-only `stripopreturns` RPC against a real node: it strips, the
//! strip survives a restart, a kill between the record and the punch leaves
//! a consistent block that the next call finishes, and a corrupt stored copy
//! is refused. Then the RPC surfaces that read a stripped block: each answers
//! from the record, or refuses when it needs the stripped bytes.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

mod common;
use common::{DeterministicWallet, TestNode, find_available_port, fresh_test_datadir, test_timeout};

const THRESHOLD: u64 = 4096;
/// Big enough to cover whole 4 KiB filesystem blocks whatever its alignment.
const PAYLOAD: usize = 20_000;
const PAYLOAD_BYTE: u8 = 0x5a;

fn mine(node: &TestNode, n: u64, addr: &str) -> Vec<String> {
    let resp = node.rpc_ok("generatetoaddress", vec![serde_json::json!(n), serde_json::json!(addr)]);
    resp.as_array().unwrap().iter().map(|h| h.as_str().unwrap().to_string()).collect()
}

/// Mine a block whose second transaction carries a `PAYLOAD`-byte
/// OP_RETURN, bury it under ten more, and return its hash. Spends the
/// coinbase of the first block it mines, so it can be called again.
fn block_with_a_big_op_return(node: &TestNode) -> String {
    use bitcoin::blockdata::opcodes::all::OP_RETURN;
    use bitcoin::script::{Builder, PushBytesBuf};

    let wallet = DeterministicWallet::from_secret([0x5b; 32]);
    let addr = wallet.address.to_string();
    let coinbase = node.rpc_ok("getblockcount", vec![]).as_u64().unwrap() + 1;
    mine(node, 101, &addr);
    let data = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(PushBytesBuf::try_from(vec![PAYLOAD_BYTE; PAYLOAD - 4]).unwrap())
        .into_script();
    assert_eq!(data.len(), PAYLOAD);
    let (raw, txid) = common::build_signed_p2wpkh_spend_of_coinbases(
        node,
        &[(coinbase, &wallet)],
        &[wallet.address.script_pubkey(), data],
        100_000,
    );
    // The helper splits the value across both outputs, so the OP_RETURN
    // burns half the coinbase: allow it.
    node.rpc_ok(
        "sendrawtransaction",
        vec![serde_json::json!(raw), serde_json::json!(0.1), serde_json::json!(50)],
    );
    let hash = mine(node, 1, &addr).remove(0);
    let block = node.rpc_ok("getblock", vec![serde_json::json!(hash), serde_json::json!(1)]);
    assert!(
        block["tx"].as_array().unwrap().iter().any(|t| t.as_str() == Some(txid.as_str())),
        "premise: the OP_RETURN transaction is in the block"
    );
    mine(node, 10, &addr);
    hash
}

fn strip(node: &TestNode, hash: &str) -> Result<serde_json::Value, serde_json::Value> {
    let resp = node
        .rpc_call_with_params("stripopreturns", vec![serde_json::json!(hash), serde_json::json!(THRESHOLD)])
        .expect("rpc transport");
    if resp["error"].is_null() {
        Ok(resp["result"].clone())
    } else {
        Err(resp["error"].clone())
    }
}

fn blocks_dir(node: &TestNode) -> PathBuf {
    node.datadir.join("regtest").join("blocks")
}

/// Every `blk*.dat`, decoded through `xor.dat`, concatenated.
fn block_files(dir: &Path) -> Vec<u8> {
    let key = std::fs::read(dir.join("xor.dat")).unwrap_or_else(|_| vec![0; 8]);
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("blk") && n.ends_with(".dat"))
        .collect();
    names.sort();
    let mut all = Vec::new();
    for n in names {
        let mut data = std::fs::read(dir.join(n)).unwrap();
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= key[i % 8];
        }
        all.extend(data);
    }
    all
}

/// Whether a run of `len` payload bytes is still in the block files.
fn payload_run_on_disk(node: &TestNode, len: usize) -> bool {
    let needle = vec![PAYLOAD_BYTE; len];
    block_files(&blocks_dir(node)).windows(len).any(|w| w == needle.as_slice())
}

/// Whether the whole payload is still in the block files.
fn payload_on_disk(node: &TestNode) -> bool {
    payload_run_on_disk(node, PAYLOAD - 4)
}

/// Bytes allocated to the block files.
fn allocated(node: &TestNode) -> u64 {
    std::fs::read_dir(blocks_dir(node))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("blk"))
        .map(|e| e.metadata().unwrap().blocks() * 512)
        .sum()
}

fn has_corrupt_warning(node: &TestNode) -> bool {
    let resp = node.rpc_call("getwarnings").expect("getwarnings");
    resp["result"].to_string().contains("blockdata.corrupt.")
}

/// The raw block is unavailable once stripped: never the zeroed bytes.
fn assert_raw_block_unavailable(node: &TestNode, hash: &str) {
    let resp = node
        .rpc_call_with_params("getblock", vec![serde_json::json!(hash), serde_json::json!(0)])
        .unwrap();
    assert!(!resp["error"].is_null(), "a stripped block is not served raw: {resp}");
    let header = node.rpc_ok("getblockheader", vec![serde_json::json!(hash)]);
    assert_eq!(header["hash"], *hash, "its header is still served");
}

#[test]
fn stripopreturns_needs_allowteststrip() {
    let mut node = TestNode::start(&[]);
    let hash = node.rpc_ok("getblockhash", vec![serde_json::json!(0)]);
    let err = strip(&node, hash.as_str().unwrap()).unwrap_err();
    assert_eq!(err["code"], -32601, "not registered: {err}");
    let help = node.rpc_ok("help", vec![]);
    assert!(!help.as_str().unwrap().contains("stripopreturns"), "never advertised");
    node.stop();

    // Paired with a node where it is registered: the same call answers.
    let mut node = TestNode::start(&["--allowteststrip"]);
    let hash = node.rpc_ok("getblockhash", vec![serde_json::json!(0)]);
    let err = strip(&node, hash.as_str().unwrap()).unwrap_err();
    assert_ne!(err["code"], -32601, "registered: {err}");
    let help = node.rpc_ok("help", vec![]);
    assert!(!help.as_str().unwrap().contains("stripopreturns"), "never advertised");
    node.stop();
}

#[test]
fn allowteststrip_is_refused_off_regtest() {
    let datadir = fresh_test_datadir("satd-allowteststrip-signet");
    let stderr = datadir.join("stderr.log");
    let _ = std::fs::create_dir_all(&datadir);
    let mut child = Command::new(env!("CARGO_BIN_EXE_satd"))
        .arg("--signet")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", find_available_port()))
        .arg(format!("--port={}", find_available_port()))
        .arg("--connect=0")
        .arg("--allowteststrip")
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .expect("run satd");
    let deadline = Instant::now() + test_timeout(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let text = std::fs::read_to_string(&stderr).unwrap_or_default();
    assert_eq!(status.and_then(|s| s.code()), Some(1), "refused at startup: {text}");
    assert!(text.contains("-allowteststrip"), "{text}");
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Strip, then restart: the block is still stripped, reads through its
/// record (a repeat strip verifies the record against the bytes), and no
/// corruption is reported.
#[test]
fn a_stripped_block_stays_stripped_across_a_restart() {
    let rpcport = find_available_port();
    let datadir = fresh_test_datadir("satd-strip-restart");
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--allowteststrip"]);
    let hash = block_with_a_big_op_return(&node);
    assert!(payload_on_disk(&node), "premise: the payload is on disk");
    let before = allocated(&node);

    let out = strip(&node, &hash).expect("strip");
    assert_eq!(out["outcome"], "stripped", "{out}");
    assert_eq!(out["txs"], 1);
    assert_eq!(out["outputs"], 1);
    assert_eq!(out["span_bytes"], PAYLOAD as u64 - 1);
    assert!(out["freed_bytes"].as_u64().unwrap() >= 4096, "{out}");
    assert!(!payload_on_disk(&node), "the payload is gone");
    let after = allocated(&node);
    assert!(after < before, "the punch gave space back: {before} -> {after}");
    assert_raw_block_unavailable(&node, &hash);
    assert!(!has_corrupt_warning(&node));
    node.stop();

    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--allowteststrip"]);
    assert!(!payload_on_disk(&node));
    assert_raw_block_unavailable(&node, &hash);
    let out = strip(&node, &hash).expect("strip after the restart");
    assert_eq!(out["outcome"], "redone", "{out}");
    assert!(!has_corrupt_warning(&node));
    node.stop();
}

/// A kill once the record is durable and before the punch: after the
/// restart the block reads as stripped (the record zero-fills the intact
/// bytes), nothing is reported corrupt, and the next strip punches it.
#[test]
fn a_kill_between_the_record_and_the_punch_is_finished_by_the_next_strip() {
    let rpcport = find_available_port();
    let datadir = fresh_test_datadir("satd-strip-failpoint");
    let mut node = TestNode::start_with_datadir_env(
        &datadir,
        rpcport,
        &["--allowteststrip"],
        &[("SATD_TEST_FAILPOINT", "strip-after-record")],
    );
    let hash = block_with_a_big_op_return(&node);
    let _ = node.rpc_call_with_params("stripopreturns", vec![serde_json::json!(hash), serde_json::json!(THRESHOLD)]);
    let deadline = Instant::now() + test_timeout(60);
    let status = loop {
        if let Some(status) = node.process.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the failpoint did not abort the node");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(!status.success(), "aborted: {status}");
    let log = std::fs::read_to_string(&node.stderr_log).unwrap_or_default();
    assert!(log.contains("aborting with a durable strip record"), "{log}");
    assert!(payload_on_disk(&node), "nothing was punched");

    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--allowteststrip"]);
    assert_raw_block_unavailable(&node, &hash);
    assert!(!has_corrupt_warning(&node));
    let out = strip(&node, &hash).expect("strip after the kill");
    assert_eq!(out["outcome"], "redone", "{out}");
    assert!(!payload_on_disk(&node), "the redo punched it");
    assert!(!has_corrupt_warning(&node));
    node.stop();
}

/// A stored copy whose bytes no longer match its header is never stripped,
/// and the refusal raises the corruption warning.
#[test]
fn a_corrupt_stored_copy_is_refused_with_a_warning() {
    let rpcport = find_available_port();
    let datadir = fresh_test_datadir("satd-strip-corrupt");
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--allowteststrip"]);
    let hash = block_with_a_big_op_return(&node);
    node.stop();

    // Flip a byte of the payload. The transaction still parses and the
    // header still hashes, but the txid no longer reproduces the merkle
    // root.
    let dir = blocks_dir(&node);
    let key = std::fs::read(dir.join("xor.dat")).unwrap_or_else(|_| vec![0; 8]);
    let needle = vec![PAYLOAD_BYTE; PAYLOAD - 4];
    let mut flipped = false;
    for entry in std::fs::read_dir(&dir).unwrap().filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("blk") && name.ends_with(".dat")) {
            continue;
        }
        let mut data = std::fs::read(entry.path()).unwrap();
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= key[i % 8];
        }
        if let Some(at) = data.windows(needle.len()).position(|w| w == needle.as_slice()) {
            data[at + 10] ^= 0x01;
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= key[i % 8];
            }
            std::fs::write(entry.path(), data).unwrap();
            flipped = true;
        }
    }
    assert!(flipped, "premise: found the payload");

    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--allowteststrip"]);
    let err = strip(&node, &hash).unwrap_err();
    assert!(err["message"].as_str().unwrap().contains("check_block"), "{err}");
    let warnings = node.rpc_call("getwarnings").unwrap().to_string();
    assert!(warnings.contains(&format!("blockdata.corrupt.{hash}")), "{warnings}");
    assert!(payload_run_on_disk(&node, PAYLOAD - 20), "nothing was punched");
    node.stop();
}

/// The same strip on a datadir with a blocks-dir xor key (`-blocksxor=1`),
/// where a punched span decodes to the key rather than to zeros.
#[test]
fn a_strip_under_blocksxor_reads_through_its_record() {
    let mut node = TestNode::start(&["--allowteststrip", "--blocksxor=1"]);
    let key = std::fs::read(blocks_dir(&node).join("xor.dat")).unwrap();
    assert_ne!(key, vec![0u8; 8], "premise: a nonzero key");
    let hash = block_with_a_big_op_return(&node);
    let out = strip(&node, &hash).expect("strip");
    assert_eq!(out["outcome"], "stripped", "{out}");
    assert!(!payload_on_disk(&node));
    assert_raw_block_unavailable(&node, &hash);
    let out = strip(&node, &hash).expect("a repeat verifies the record");
    assert_eq!(out["outcome"], "redone", "{out}");
    assert!(!has_corrupt_warning(&node));
    node.stop();
}

/// A block holding a stripped transaction and an intact one, both spending a
/// coinbase, buried ten deep. Returns the block hash and the two
/// transactions' `(txid, raw hex)`.
struct MixedBlock {
    hash: String,
    stripped: (String, String),
    intact: (String, String),
}

fn block_with_a_stripped_and_an_intact_tx(node: &TestNode) -> MixedBlock {
    let wallet = DeterministicWallet::from_secret([0x5c; 32]);
    let spk = wallet.address.script_pubkey();
    mixed_block(node, &wallet, spk)
}

/// [`block_with_a_stripped_and_an_intact_tx`], with the stripped
/// transaction's first output paying `first_output`.
fn mixed_block(node: &TestNode, wallet: &DeterministicWallet, first_output: bitcoin::ScriptBuf) -> MixedBlock {
    use bitcoin::blockdata::opcodes::all::OP_RETURN;
    use bitcoin::script::{Builder, PushBytesBuf};

    let addr = wallet.address.to_string();
    mine(node, 102, &addr);
    let data = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(PushBytesBuf::try_from(vec![PAYLOAD_BYTE; PAYLOAD - 4]).unwrap())
        .into_script();
    let (stripped_raw, stripped) = common::build_signed_p2wpkh_spend_of_coinbases(
        node,
        &[(1, wallet)],
        &[first_output, data],
        100_000,
    );
    let (intact_raw, intact) = common::build_signed_p2wpkh_spend_of_coinbases(
        node,
        &[(2, wallet)],
        &[wallet.address.script_pubkey()],
        100_000,
    );
    node.rpc_ok(
        "sendrawtransaction",
        vec![serde_json::json!(stripped_raw), serde_json::json!(0.1), serde_json::json!(50)],
    );
    node.rpc_ok("sendrawtransaction", vec![serde_json::json!(intact_raw)]);
    let hash = mine(node, 1, &addr).remove(0);
    let block = node.rpc_ok("getblock", vec![serde_json::json!(hash), serde_json::json!(1)]);
    assert_eq!(block["tx"].as_array().unwrap().len(), 3, "premise: both are in the block: {block}");
    mine(node, 10, &addr);
    MixedBlock {
        hash,
        stripped: (stripped, stripped_raw),
        intact: (intact, intact_raw),
    }
}

/// `tx`, a verbose transaction from before the strip, as it must read after:
/// no `hex`, the flag, and output `vout` reduced to its bare `OP_RETURN`.
fn as_stripped(mut tx: serde_json::Value, vout: usize, script_len: usize) -> serde_json::Value {
    tx.as_object_mut().unwrap().remove("hex");
    tx["opreturn_stripped"] = serde_json::json!(true);
    tx["vout"][vout]["scriptPubKey"] = serde_json::json!({
        "asm": "OP_RETURN",
        "hex": "6a",
        "type": "nulldata",
        "stripped_size": script_len,
    });
    tx
}

fn rpc_err(node: &TestNode, method: &str, params: Vec<serde_json::Value>) -> serde_json::Value {
    let resp = node.rpc_call_with_params(method, params).expect("rpc transport");
    assert!(!resp["error"].is_null(), "{method} must refuse: {resp}");
    resp["error"].clone()
}

/// Every RPC that reads a block, on a block with a stripped and an intact
/// transaction. Each answer is captured before the strip and compared with
/// the answer after it: equal, or equal but for exactly what stripping
/// changes. Each refusal is paired with the same call on the intact
/// transaction, which must still succeed.
#[test]
fn rpc_surfaces_read_a_stripped_block_through_its_record() {
    use serde_json::json;

    let mut node = TestNode::start(&["--allowteststrip", "--txindex", "--txospenderindex"]);
    let b = block_with_a_stripped_and_an_intact_tx(&node);
    let (stripped, _) = &b.stripped;
    let (intact, intact_raw) = &b.intact;
    let i = |v: &serde_json::Value, txid: &str| {
        v["tx"].as_array().unwrap().iter().position(|t| t["txid"] == txid).unwrap()
    };
    let getblock = |v: u32| node.rpc_ok("getblock", vec![json!(b.hash), json!(v)]);
    let rawtx = |txid: &str, verbosity: u32, block: bool| {
        let mut params = vec![json!(txid), json!(verbosity)];
        if block {
            params.push(json!(b.hash));
        }
        node.rpc_call_with_params("getrawtransaction", params).expect("rpc transport")
    };
    let proof = |txid: &str| node.rpc_ok("gettxoutproof", vec![json!([txid])]);
    let spender = |height: u64| {
        let coinbase = common::coinbase_txid_at(&node, height);
        node.rpc_call_with_params(
            "gettxspendingprevout",
            vec![json!([{"txid": coinbase, "vout": 0}]), json!({"return_spending_tx": true})],
        )
        .expect("rpc transport")
    };
    common::poll_until(
        || node.rpc_ok("getindexinfo", vec![])["txospenderindex"]["synced"] == json!(true),
        test_timeout(30),
        "txospenderindex never synced",
    );

    let before_1 = getblock(1);
    let before_2 = getblock(2);
    let before_3 = getblock(3);
    let before_stats = node.rpc_ok("getblockstats", vec![json!(b.hash)]);
    let before_tx = rawtx(stripped, 2, false)["result"].clone();
    let before_tx_in_block = rawtx(stripped, 2, true)["result"].clone();
    let before_intact = rawtx(intact, 2, false)["result"].clone();
    let before_proof = proof(stripped);
    let before_spender = spender(2)["result"].clone();
    let vout = before_tx["vout"]
        .as_array()
        .unwrap()
        .iter()
        .position(|o| o["scriptPubKey"]["type"] == "nulldata")
        .unwrap();

    let out = strip(&node, &b.hash).expect("strip");
    assert_eq!(out["outcome"], "stripped", "{out}");
    assert!(!payload_on_disk(&node), "premise: the payload is gone");

    // getblock 0: the raw block is never served; the next block's still is.
    let err = rpc_err(&node, "getblock", vec![json!(b.hash), json!(0)]);
    assert_eq!(err["code"], -1, "{err}");
    assert_eq!(err["message"], "Block not available (pruned data)");
    let next = before_1["nextblockhash"].clone();
    assert!(node.rpc_ok("getblock", vec![next, json!(0)]).is_string());

    // getblock 1: the same, txids and sizes included, plus the summary.
    let mut expected = before_1.clone();
    expected["opreturn_stripped"] = json!({"transactions": 1, "outputs": 1, "bytes": PAYLOAD - 1});
    assert_eq!(getblock(1), expected);

    // getblock 2 and 3: the stripped tx changes as `as_stripped` says, the
    // coinbase and the intact tx not at all. Fees and prevouts come from
    // undo data, so they are unchanged.
    for (v, before) in [(2, &before_2), (3, &before_3)] {
        let mut expected = before.clone();
        let at = i(before, stripped);
        expected["tx"][at] = as_stripped(before["tx"][at].clone(), vout, PAYLOAD);
        expected["opreturn_stripped"] = json!({"transactions": 1, "outputs": 1, "bytes": PAYLOAD - 1});
        assert_eq!(getblock(v), expected, "getblock {v}");
    }

    // getrawtransaction: hex is refused for the stripped tx, through the
    // txindex and with a block hash; the intact tx's is served.
    for block in [false, true] {
        let resp = rawtx(stripped, 0, block);
        assert_eq!(resp["error"]["code"], -1, "{resp}");
        assert_eq!(resp["error"]["message"], "Transaction data not available (OP_RETURN data stripped)");
        assert_eq!(rawtx(intact, 0, block)["result"], json!(intact_raw));
    }
    // Verbose reads like getblock 2's entry, through either path.
    assert_eq!(rawtx(stripped, 2, false)["result"], as_stripped(before_tx, vout, PAYLOAD));
    assert_eq!(rawtx(stripped, 2, true)["result"], as_stripped(before_tx_in_block, vout, PAYLOAD));
    assert_eq!(rawtx(intact, 2, false)["result"], before_intact);

    // gettxoutproof needs only the txids: the same proof, and it verifies.
    assert_eq!(proof(stripped), before_proof);
    assert_eq!(node.rpc_ok("verifytxoutproof", vec![before_proof]), json!([stripped]));
    let intact_proof = proof(intact);
    assert_eq!(node.rpc_ok("verifytxoutproof", vec![intact_proof]), json!([intact]));

    // getblockstats: identical.
    assert_eq!(node.rpc_ok("getblockstats", vec![json!(b.hash)]), before_stats);

    // verifychain reads the stripped block and finds it sound.
    assert_eq!(node.rpc_ok("verifychain", vec![json!(4), json!(20)]), json!(true));

    // gettxspendingprevout: the stripped spender's bytes are refused; the
    // intact one's are served as before.
    let resp = spender(1);
    assert_eq!(resp["error"]["code"], -1, "{resp}");
    assert_eq!(resp["error"]["message"], "Transaction data not available (OP_RETURN data stripped)");
    assert_eq!(spender(2)["result"], before_spender);

    // Nothing above was reported as corruption or an index mismatch.
    assert!(!has_corrupt_warning(&node));
    node.stop();
}

/// An HTTP GET against Esplora: `(status, body)`.
fn esplora_get(port: u16, path: &str) -> (u16, String) {
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{port}{path}"))
        .send()
        .unwrap();
    (resp.status().as_u16(), resp.text().unwrap())
}

/// A 200 from Esplora, as JSON, or as a string for a plain-text endpoint.
fn esplora_json(port: u16, path: &str) -> serde_json::Value {
    let (status, body) = esplora_get(port, path);
    assert_eq!(status, 200, "{path}: {body}");
    serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body))
}

/// A line-oriented Electrum client: one request, then its response, skipping
/// notifications; or, for `blockchain.tweaks.subscribe`, every line up to the
/// `done` notification.
struct Electrum {
    reader: std::io::BufReader<std::net::TcpStream>,
    writer: std::net::TcpStream,
}

impl Electrum {
    fn connect(port: u16) -> Self {
        let stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("electrum connect");
        stream.set_read_timeout(Some(test_timeout(20))).unwrap();
        let reader = std::io::BufReader::new(stream.try_clone().unwrap());
        Self { reader, writer: stream }
    }

    fn line(&mut self) -> serde_json::Value {
        use std::io::BufRead as _;
        let mut line = String::new();
        assert!(self.reader.read_line(&mut line).unwrap() > 0, "electrum closed the connection");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON: {line:?} ({e})"))
    }

    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        use std::io::Write as _;
        let req = serde_json::json!({"id": 1, "method": method, "params": params});
        writeln!(self.writer, "{req}").unwrap();
        loop {
            let resp = self.line();
            if resp.get("id").is_some() {
                return resp;
            }
        }
    }

    /// The response to `blockchain.tweaks.subscribe` and every notification
    /// through the one that ends the chunk.
    fn tweaks(&mut self, height: u64) -> Vec<serde_json::Value> {
        let mut out = vec![self.call("blockchain.tweaks.subscribe", serde_json::json!([height, 1, true]))];
        loop {
            let n = self.line();
            let done = n["params"][0]["message"] == "done";
            out.push(n);
            if done {
                return out;
            }
        }
    }
}

/// `tx`, an Esplora transaction from before the strip, as it must read after:
/// the flag, and output `vout` described as its bare `OP_RETURN`.
fn as_stripped_esplora(mut tx: serde_json::Value, vout: usize, script_len: usize) -> serde_json::Value {
    tx["opreturn_stripped"] = serde_json::json!(true);
    let out = &mut tx["vout"][vout];
    out["scriptpubkey"] = serde_json::json!("6a");
    out["scriptpubkey_asm"] = serde_json::json!("OP_RETURN");
    out["scriptpubkey_type"] = serde_json::json!("op_return");
    out["scriptpubkey_address"] = serde_json::Value::Null;
    out["scriptpubkey_stripped_size"] = serde_json::json!(script_len);
    tx
}

/// Esplora and Electrum on a block with a stripped and an intact transaction,
/// the stripped one silent-payment eligible. As for the RPCs, each answer is
/// captured before the strip and compared with the answer after it, and each
/// refusal is paired with the same call on the intact transaction.
#[test]
fn esplora_and_electrum_read_a_stripped_block_through_its_record() {
    use serde_json::json;

    let esplora = find_available_port();
    let electrum = find_available_port();
    let esplora_bind = format!("--esplorabind=127.0.0.1:{esplora}");
    let electrum_bind = format!("--electrumbind=127.0.0.1:{electrum}");
    let mut node = TestNode::start(&[
        "--allowteststrip",
        "--txindex",
        "--addressindex",
        "--silentpaymentindex=1",
        "--esplora=1",
        &esplora_bind,
        "--electrum=1",
        &electrum_bind,
    ]);
    let wallet = DeterministicWallet::from_secret([0x5e; 32]);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (_, p2tr) = common::p2tr_keypath_output(&secp, [0x3f; 32]);
    let b = mixed_block(&node, &wallet, p2tr);
    let (stripped, _) = &b.stripped;
    let (intact, intact_raw) = &b.intact;
    let height = node.rpc_ok("getblockheader", vec![json!(b.hash)])["height"].as_u64().unwrap();
    common::poll_until(
        || {
            let info = node.rpc_ok("getindexinfo", vec![]);
            info.as_object().is_some_and(|m| !m.is_empty() && m.values().all(|i| i["synced"] == true))
        },
        test_timeout(60),
        "indexes never synced",
    );
    let addr = wallet.address.to_string();
    let get = |path: &str| esplora_json(esplora, path);
    let paths = [
        format!("/block/{}", b.hash),
        format!("/block/{}/txids", b.hash),
        format!("/block/{}/txid/1", b.hash),
        format!("/block/{}/txid/2", b.hash),
        format!("/blocks/{height}"),
        format!("/tx/{stripped}/status"),
        format!("/tx/{stripped}/merkle-proof"),
        format!("/tx/{stripped}/outspends"),
        format!("/tx/{intact}"),
        format!("/tx/{intact}/merkle-proof"),
    ];
    let before: Vec<_> = paths.iter().map(|p| get(p)).collect();
    let (_, before_merkleblock) = esplora_get(esplora, &format!("/tx/{stripped}/merkleblock-proof"));
    let before_tx = get(&format!("/tx/{stripped}"));
    let before_txs = get(&format!("/block/{}/txs", b.hash));
    let before_history = get(&format!("/address/{addr}/txs"));
    let vout = before_tx["vout"]
        .as_array()
        .unwrap()
        .iter()
        .position(|o| o["scriptpubkey_type"] == "op_return")
        .unwrap();

    let mut el = Electrum::connect(electrum);
    let before_el_verbose = el.call("blockchain.transaction.get", json!([stripped, true]))["result"].clone();
    let before_el_merkle = el.call("blockchain.transaction.get_merkle", json!([stripped, height]));
    let id_from_pos = |el: &mut Electrum| {
        [1, 2].map(|pos| el.call("blockchain.transaction.id_from_pos", json!([height, pos, true])))
    };
    let before_el_pos = id_from_pos(&mut el);
    let before_el_tweaks = el.tweaks(height);
    assert!(
        before_el_tweaks.iter().any(|l| l.to_string().contains(stripped.as_str())),
        "premise: the stripped tx has a tweak row: {before_el_tweaks:?}"
    );

    let out = strip(&node, &b.hash).expect("strip");
    assert_eq!(out["outcome"], "stripped", "{out}");
    assert!(!payload_on_disk(&node), "premise: the payload is gone");

    // Esplora: everything that needs only txids, sizes and values is unchanged.
    for (path, want) in paths.iter().zip(&before) {
        assert_eq!(&get(path), want, "{path}");
    }
    assert_eq!(
        esplora_get(esplora, &format!("/tx/{stripped}/merkleblock-proof")),
        (200, before_merkleblock),
    );
    // The stripped transaction renders without its payload, wherever it is listed.
    let want_tx = as_stripped_esplora(before_tx, vout, PAYLOAD);
    assert_eq!(get(&format!("/tx/{stripped}")), want_tx);
    let mut want_txs = before_txs.clone();
    for t in want_txs.as_array_mut().unwrap() {
        if t["txid"] == json!(stripped) {
            *t = want_tx.clone();
        }
    }
    assert_ne!(want_txs, before_txs, "premise: the page lists the stripped tx");
    assert_eq!(get(&format!("/block/{}/txs", b.hash)), want_txs);
    let mut want_history = before_history.clone();
    for t in want_history.as_array_mut().unwrap() {
        if t["txid"] == json!(stripped) {
            *t = want_tx.clone();
        }
    }
    assert_ne!(want_history, before_history, "premise: the history lists the stripped tx");
    assert_eq!(get(&format!("/address/{addr}/txs")), want_history);
    // Raw bytes are refused, paired with the intact tx and the next block.
    let gone = |path: String, body: &str| {
        assert_eq!(esplora_get(esplora, &path), (404, body.to_string()), "{path}");
    };
    gone(format!("/block/{}/raw", b.hash), "block data not available (OP_RETURN data stripped)");
    gone(format!("/tx/{stripped}/hex"), "transaction data not available (OP_RETURN data stripped)");
    gone(format!("/tx/{stripped}/raw"), "transaction data not available (OP_RETURN data stripped)");
    let next = node.rpc_ok("getblockhash", vec![json!(height + 1)]);
    assert_eq!(esplora_get(esplora, &format!("/block/{}/raw", next.as_str().unwrap())).0, 200);
    assert_eq!(esplora_get(esplora, &format!("/tx/{intact}/hex")), (200, intact_raw.clone()));
    assert_eq!(esplora_get(esplora, &format!("/tx/{intact}/raw")).0, 200);

    // Electrum: the hex is refused and the intact tx's served; verbose reads as
    // getrawtransaction's does; proofs and tweaks are unchanged.
    let resp = el.call("blockchain.transaction.get", json!([stripped]));
    assert_eq!(
        resp["error"]["message"], "transaction data not available (OP_RETURN data stripped)",
        "{resp}"
    );
    assert_eq!(el.call("blockchain.transaction.get", json!([intact]))["result"], json!(intact_raw));
    assert_eq!(
        el.call("blockchain.transaction.get", json!([stripped, true]))["result"],
        as_stripped(before_el_verbose, vout, PAYLOAD)
    );
    assert_eq!(el.call("blockchain.transaction.get_merkle", json!([stripped, height])), before_el_merkle);
    assert_eq!(id_from_pos(&mut el), before_el_pos);
    assert_eq!(el.tweaks(height), before_el_tweaks);

    assert!(!has_corrupt_warning(&node));
    node.stop();
}

/// A chainstate's rows, by column family.
type Dump = std::collections::BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>>;

/// Every column family of a cleanly stopped node's chainstate, as sorted
/// `(key, value)` rows, except the strip records themselves.
fn dump_chainstate(datadir: &Path) -> Dump {
    use rocksdb::{DB, IteratorMode, Options};

    let net_dir = datadir.join("regtest");
    assert!(net_dir.join(".clean_shutdown").exists(), "dump needs a clean stop");
    let path = net_dir.join("chainstate");
    let opts = Options::default();
    let cfs = DB::list_cf(&opts, &path).expect("list column families");
    let db = DB::open_cf_for_read_only(&opts, &path, &cfs, false).expect("open chainstate");
    let mut out = std::collections::BTreeMap::new();
    for name in cfs.iter().filter(|n| *n != "opreturn_strip") {
        let cf = db.cf_handle(name).unwrap();
        let rows = db
            .iterator_cf(&cf, IteratorMode::Start)
            .map(|item| {
                let (k, v) = item.expect("iterate");
                (k.to_vec(), v.to_vec())
            })
            .collect();
        out.insert(name.clone(), rows);
    }
    out
}

/// The first difference between two dumps, for a readable failure.
fn first_difference(
    a: &Dump,
    b: &Dump,
) -> Option<String> {
    let names: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
    for name in names {
        let (ra, rb) = (a.get(name), b.get(name));
        if ra == rb {
            continue;
        }
        let (ra, rb) = (ra.cloned().unwrap_or_default(), rb.cloned().unwrap_or_default());
        for i in 0..ra.len().max(rb.len()) {
            if ra.get(i) != rb.get(i) {
                let show = |r: Option<&(Vec<u8>, Vec<u8>)>| {
                    r.map(|(k, v)| format!("{} => {}", hex::encode(k), hex::encode(v)))
                };
                return Some(format!(
                    "column family {name}: {} vs {} rows; row {i}: {:?} vs {:?}",
                    ra.len(),
                    rb.len(),
                    show(ra.get(i)),
                    show(rb.get(i))
                ));
            }
        }
    }
    None
}

const INDEXES: &[&str] = &["--txindex", "--addressindex", "--blockfilterindex", "--silentpaymentindex=1"];

fn start_indexed(datadir: &Path, rpcport: u16, extra: &[&str]) -> TestNode {
    let mut args: Vec<&str> = vec!["--allowteststrip"];
    args.extend_from_slice(INDEXES);
    args.extend_from_slice(extra);
    let node = TestNode::start_with_datadir(datadir, rpcport, &args);
    common::poll_until(
        || {
            let info = node.rpc_ok("getindexinfo", vec![]);
            info.as_object().is_some_and(|m| !m.is_empty() && m.values().all(|i| i["synced"] == true))
        },
        test_timeout(60),
        "indexes never synced",
    );
    node
}

/// Replay the chain with `flag`, stop, and dump it.
fn replay_and_dump(
    datadir: &Path,
    rpcport: u16,
    flag: &str,
    tip: &str,
) -> Dump {
    let mut node = start_indexed(datadir, rpcport, &[flag]);
    assert_eq!(node.rpc_ok("getbestblockhash", vec![]), serde_json::json!(tip), "{flag} reached the tip");
    assert!(!has_corrupt_warning(&node));
    let warnings = node.rpc_call("getwarnings").unwrap().to_string();
    assert!(!warnings.contains("reindex.halted"), "{flag} halted: {warnings}");
    node.stop();
    // Dropping a node removes its datadir; this one is reused.
    node.datadir = PathBuf::new();
    dump_chainstate(datadir)
}

/// The acceptance test for replaying stripped blocks (plan §2.11 step 5).
///
/// A chain with every index on carries two blocks of big OP_RETURNs. One of
/// the stripped transactions is silent-payment eligible, and a later block
/// spends outputs of both. The chain is replayed with `-reindex-chainstate`
/// and with `-reindex` before the strip and again after it, and every column
/// family but the strip records must come out byte-identical: the coins,
/// undo data, block index, txindex, address, filter and silent-payment rows.
#[test]
fn a_stripped_chain_replays_to_the_same_chainstate() {
    use bitcoin::blockdata::opcodes::all::OP_RETURN;
    use bitcoin::script::{Builder, PushBytesBuf};
    use serde_json::json;

    let rpcport = find_available_port();
    let datadir = fresh_test_datadir("satd-strip-replay");
    let mut node = start_indexed(&datadir, rpcport, &[]);
    let wallet = DeterministicWallet::from_secret([0x5d; 32]);
    let addr = wallet.address.to_string();
    mine(&node, 104, &addr);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (kp, p2tr) = common::p2tr_keypath_output(&secp, [0x3e; 32]);
    let data = |byte: u8| {
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::try_from(vec![byte; PAYLOAD - 4]).unwrap())
            .into_script()
    };
    let send = |raw: &str| {
        node.rpc_ok("sendrawtransaction", vec![json!(raw), json!(0.1), json!(50)]);
    };
    const FEE: u64 = 100_000;

    // Block X: two stripped transactions. `sp` is silent-payment eligible
    // (a P2WPKH input and a taproot output); `plain` pays the wallet.
    let (sp_raw, sp) = common::build_signed_p2wpkh_spend_of_coinbases(
        &node,
        &[(1, &wallet)],
        &[p2tr.clone(), data(PAYLOAD_BYTE)],
        FEE,
    );
    let (plain_raw, _) = common::build_signed_p2wpkh_spend_of_coinbases(
        &node,
        &[(2, &wallet)],
        &[wallet.address.script_pubkey(), data(PAYLOAD_BYTE ^ 0xff)],
        FEE,
    );
    send(&sp_raw);
    send(&plain_raw);
    let x = mine(&node, 1, &addr).remove(0);

    // Block Y: spends the taproot output of `sp`, and a third stripped
    // transaction.
    let sp_value = (50 * 100_000_000 - FEE) / 2;
    let (spend_raw, spend) = common::build_signed_p2tr_keypath_spend(
        &secp,
        &kp,
        bitcoin::OutPoint { txid: sp.parse().unwrap(), vout: 0 },
        p2tr.clone(),
        sp_value,
        wallet.address.script_pubkey(),
        FEE,
    );
    let (third_raw, _) = common::build_signed_p2wpkh_spend_of_coinbases(
        &node,
        &[(3, &wallet)],
        &[wallet.address.script_pubkey(), data(0x33)],
        FEE,
    );
    send(&spend_raw);
    send(&third_raw);
    let y = mine(&node, 1, &addr).remove(0);
    let tip = mine(&node, 10, &addr).pop().unwrap();
    let sp_rows = node.rpc_ok("getblock", vec![json!(x), json!(1)]);
    assert!(sp_rows["tx"].as_array().unwrap().iter().any(|t| t == &json!(sp)));
    assert!(
        node.rpc_ok("getblock", vec![json!(y), json!(1)])["tx"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == &json!(spend)),
        "premise: the spend of a to-be-stripped output is mined"
    );
    node.stop();

    let chainstate_unstripped = replay_and_dump(&datadir, rpcport, "--reindex-chainstate", &tip);
    let reindex_unstripped = replay_and_dump(&datadir, rpcport, "--reindex", &tip);

    let mut node = start_indexed(&datadir, rpcport, &[]);
    for hash in [&x, &y] {
        let out = strip(&node, hash).expect("strip");
        assert_eq!(out["outcome"], "stripped", "{out}");
    }
    assert!(!payload_on_disk(&node), "premise: the payloads are gone");
    node.stop();

    let chainstate_stripped = replay_and_dump(&datadir, rpcport, "--reindex-chainstate", &tip);
    if let Some(diff) = first_difference(&chainstate_unstripped, &chainstate_stripped) {
        panic!("-reindex-chainstate over stripped blocks differs: {diff}");
    }
    let reindex_stripped = replay_and_dump(&datadir, rpcport, "--reindex", &tip);
    if let Some(diff) = first_difference(&reindex_unstripped, &reindex_stripped) {
        panic!("-reindex over stripped blocks differs: {diff}");
    }

    // The records survived both replays: the blocks still read stripped.
    let mut node = start_indexed(&datadir, rpcport, &[]);
    assert_raw_block_unavailable(&node, &x);
    assert!(!payload_on_disk(&node));
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// The column families the index backfills write.
const INDEX_CFS: &[&str] = &[
    "tx_loc",
    "txseq_txid",
    "txseq_block",
    "addr_funding_v3",
    "addr_spending_v3",
    "spent",
    "block_filter",
    "block_filter_header",
    "sp_tweaks",
];

/// Restart a chain built without indexes with `INDEXES` on, run each
/// backfill to completion, stop, and dump the index column families.
fn backfill_and_dump(datadir: &Path, rpcport: u16, tip: &str) -> Dump {
    let mut args: Vec<&str> = vec!["--allowteststrip"];
    args.extend_from_slice(INDEXES);
    let mut node = TestNode::start_with_datadir(datadir, rpcport, &args);
    for (target, key) in [
        ("address", "address"),
        ("blockfilter", "basic block filter index"),
        ("silentpayment", "silentpayments"),
    ] {
        node.rpc_ok("backfillindex", vec![serde_json::json!(target)]);
        common::poll_until(
            || node.rpc_ok("getsatdindexinfo", vec![])[key]["synced"] == true,
            test_timeout(60),
            "a backfill never completed",
        );
    }
    assert_eq!(node.rpc_ok("getbestblockhash", vec![]), serde_json::json!(tip));
    assert!(!has_corrupt_warning(&node));
    node.stop();
    node.datadir = PathBuf::new();
    let mut dump = dump_chainstate(datadir);
    dump.retain(|name, _| INDEX_CFS.contains(&name.as_str()));
    for cf in INDEX_CFS {
        assert!(dump.get(*cf).is_some_and(|rows| !rows.is_empty()), "premise: {cf} has rows");
    }
    dump
}

/// The address, filter and silent-payment backfills over stripped blocks
/// (plan §2.8, PR 5c). A chain built with no index on carries a block with two
/// stripped transactions, one silent-payment eligible, and a later block
/// spends that one's taproot output. The datadir is copied before the strip;
/// both copies then backfill every index, and the rows must be byte-identical.
/// Pass 1 of the address backfill names each output by its stored txid, so a
/// pass 1 that hashed the filled bytes would leave pass 2 unable to find the
/// spent output.
#[test]
fn index_backfills_over_stripped_blocks_match_backfills_over_intact_ones() {
    use bitcoin::blockdata::opcodes::all::OP_RETURN;
    use bitcoin::script::{Builder, PushBytesBuf};
    use serde_json::json;

    let rpcport = find_available_port();
    let stripped_dir = fresh_test_datadir("satd-strip-backfill");
    let intact_dir = fresh_test_datadir("satd-strip-backfill-intact");
    let mut node = TestNode::start_with_datadir(&stripped_dir, rpcport, &["--allowteststrip"]);
    let wallet = DeterministicWallet::from_secret([0x5f; 32]);
    let addr = wallet.address.to_string();
    mine(&node, 104, &addr);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (kp, p2tr) = common::p2tr_keypath_output(&secp, [0x40; 32]);
    let data = |byte: u8| {
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(PushBytesBuf::try_from(vec![byte; PAYLOAD - 4]).unwrap())
            .into_script()
    };
    let send = |raw: &str| {
        node.rpc_ok("sendrawtransaction", vec![json!(raw), json!(0.1), json!(50)]);
    };
    const FEE: u64 = 100_000;
    let (sp_raw, sp) = common::build_signed_p2wpkh_spend_of_coinbases(
        &node,
        &[(1, &wallet)],
        &[p2tr.clone(), data(PAYLOAD_BYTE)],
        FEE,
    );
    let (plain_raw, _) = common::build_signed_p2wpkh_spend_of_coinbases(
        &node,
        &[(2, &wallet)],
        &[wallet.address.script_pubkey(), data(PAYLOAD_BYTE ^ 0xff)],
        FEE,
    );
    send(&sp_raw);
    send(&plain_raw);
    let x = mine(&node, 1, &addr).remove(0);
    let sp_value = (50 * 100_000_000 - FEE) / 2;
    let (spend_raw, _) = common::build_signed_p2tr_keypath_spend(
        &secp,
        &kp,
        bitcoin::OutPoint { txid: sp.parse().unwrap(), vout: 0 },
        p2tr,
        sp_value,
        wallet.address.script_pubkey(),
        FEE,
    );
    send(&spend_raw);
    mine(&node, 1, &addr);
    let tip = mine(&node, 10, &addr).pop().unwrap();
    assert_eq!(node.rpc_ok("getblock", vec![json!(x), json!(1)])["tx"].as_array().unwrap().len(), 3);
    node.stop();
    node.datadir = PathBuf::new();

    let status = Command::new("cp")
        .arg("-a")
        .arg(format!("{}/.", stripped_dir.display()))
        .arg(&intact_dir)
        .status()
        .unwrap();
    assert!(status.success(), "copy the datadir");

    let mut node = TestNode::start_with_datadir(&stripped_dir, rpcport, &["--allowteststrip"]);
    let out = strip(&node, &x).expect("strip");
    assert_eq!(out["outcome"], "stripped", "{out}");
    assert_eq!(out["txs"], 2, "{out}");
    node.stop();
    node.datadir = PathBuf::new();

    let intact = backfill_and_dump(&intact_dir, rpcport, &tip);
    let stripped = backfill_and_dump(&stripped_dir, rpcport, &tip);
    if let Some(diff) = first_difference(&intact, &stripped) {
        panic!("backfill over stripped blocks differs: {diff}");
    }
    let _ = std::fs::remove_dir_all(&stripped_dir);
    let _ = std::fs::remove_dir_all(&intact_dir);
}

/// `satd-chainstate-audit` reads a stripped block through its record (PR 5e):
/// with the txindex on, its transactions are found under their recorded txids,
/// so a healthy node with a stripped block in the window is `consistent`.
#[test]
fn the_offline_audit_reads_a_stripped_block_through_its_record() {
    let rpcport = find_available_port();
    let datadir = fresh_test_datadir("satd-strip-audit");
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--allowteststrip", "--txindex"]);
    let hash = block_with_a_big_op_return(&node);
    let out = strip(&node, &hash).expect("strip");
    assert_eq!(out["outcome"], "stripped", "{out}");
    node.stop();
    node.datadir = PathBuf::new();

    let out = Command::new(env!("CARGO_BIN_EXE_satd-chainstate-audit"))
        .arg(format!("--datadir={}", datadir.join("regtest").display()))
        .arg("--window=50")
        .output()
        .expect("run the audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("checked 50 blocks"), "premise: the stripped block is in the window: {stdout}");
    assert!(stdout.trim_end().ends_with("consistent"), "{stdout}");
    let _ = std::fs::remove_dir_all(&datadir);
}

/// The tip, and each block's hash and confirmations, from `getblockheader`.
fn chain_state(node: &TestNode, hashes: &[String]) -> (serde_json::Value, Vec<serde_json::Value>) {
    let tip = node.rpc_ok("getbestblockhash", vec![]);
    let headers = hashes
        .iter()
        .map(|h| node.rpc_ok("getblockheader", vec![serde_json::json!(h)])["confirmations"].clone())
        .collect();
    (tip, headers)
}

/// `invalidateblock` refuses, before marking anything, when the rollback would
/// disconnect a stripped block (plan §2.10). Paired with an invalidation above
/// the stripped block, which goes through.
#[test]
fn invalidateblock_below_a_stripped_block_is_refused_and_changes_nothing() {
    use serde_json::json;

    let mut node = TestNode::start(&["--allowteststrip"]);
    let hash = block_with_a_big_op_return(&node);
    let out = strip(&node, &hash).expect("strip");
    assert_eq!(out["outcome"], "stripped", "{out}");
    let height = node.rpc_ok("getblockheader", vec![json!(hash)])["height"].as_u64().unwrap();
    let below = node.rpc_ok("getblockhash", vec![json!(height - 1)]).as_str().unwrap().to_string();
    let above = node.rpc_ok("getblockhash", vec![json!(height + 5)]).as_str().unwrap().to_string();
    let watched = [below.clone(), hash.clone(), above.clone()];
    let before = chain_state(&node, &watched);
    let tips = node.rpc_ok("getchaintips", vec![]);

    for target in [&below, &hash] {
        let err = rpc_err(&node, "invalidateblock", vec![json!(target)]);
        let msg = err["message"].as_str().unwrap();
        assert!(
            msg.contains(&format!("block {hash} at height {height} has stripped OP_RETURN data"))
                && msg.contains("getblockfrompeer"),
            "{err}"
        );
        assert_eq!(chain_state(&node, &watched), before, "nothing moved");
        assert_eq!(node.rpc_ok("getchaintips", vec![]), tips, "nothing was marked");
    }

    // Above the stripped block, the same call goes through.
    node.rpc_ok("invalidateblock", vec![json!(above)]);
    let tip = node.rpc_ok("getblockheader", vec![node.rpc_ok("getbestblockhash", vec![])]);
    assert_eq!(tip["height"].as_u64(), Some(height + 4));
    node.rpc_ok("reconsiderblock", vec![json!(above)]);
    assert_eq!(chain_state(&node, &watched), before);
    node.stop();
}

/// A reorg whose disconnect walk reaches a stripped block fails closed with
/// the stripped-data message and leaves the tip where it was (plan §2.10). The
/// competing chain, longer and forking below the stripped block, comes from a
/// second node through `submitblock`.
#[test]
fn a_reorg_past_a_stripped_block_fails_closed_with_the_stripped_message() {
    use serde_json::json;

    let mut node = TestNode::start(&["--allowteststrip"]);
    let hash = block_with_a_big_op_return(&node);
    let out = strip(&node, &hash).expect("strip");
    assert_eq!(out["outcome"], "stripped", "{out}");
    let height = node.rpc_ok("getblockheader", vec![json!(hash)])["height"].as_u64().unwrap();
    let tip_height = node.rpc_ok("getblockcount", vec![]).as_u64().unwrap();
    let below = node.rpc_ok("getblockhash", vec![json!(height - 1)]).as_str().unwrap().to_string();
    let watched = [below.clone(), hash.clone()];
    let before = chain_state(&node, &watched);

    // A competing chain from genesis, longer than the stripped node's.
    let mut other = TestNode::start(&[]);
    let addr = DeterministicWallet::from_secret([0x63; 32]).address.to_string();
    let fork = mine(&other, tip_height + 5, &addr);
    for h in &fork {
        let raw = other.rpc_ok("getblock", vec![json!(h), json!(0)]);
        let _ = node.rpc_call_with_params("submitblock", vec![raw]);
    }
    other.stop();

    assert_eq!(chain_state(&node, &watched), before, "the reorg did not go through");
    let log = std::fs::read_to_string(&node.stderr_log).unwrap_or_default();
    assert!(
        log.contains(&format!("block {hash} at height {height} has stripped OP_RETURN data")),
        "the reorg failure names the stripped block: {}",
        log.lines().filter(|l| l.contains("reorg")).collect::<Vec<_>>().join("\n")
    );
    assert!(!has_corrupt_warning(&node));
    node.stop();
}

/// `getblockfrompeer` restores a stripped block in place (plan §2.12, PR 7).
/// Node A strips a block that node B holds intact, then fetches it from B:
/// the raw block is served again, the strip summary is gone, the payload is
/// back in A's block files, and the punched space is allocated again. A runs
/// with a blocks-dir xor key, so the restore must encode what it writes.
#[test]
fn getblockfrompeer_restores_a_stripped_block_in_place() {
    use serde_json::json;

    let mut a = TestNode::start(&["--allowteststrip", "--blocksxor=1"]);
    let hash = block_with_a_big_op_return(&a);
    let tip = a.rpc_ok("getbestblockhash", vec![]);
    let raw = a.rpc_ok("getblock", vec![json!(hash), json!(0)]);

    let mut b = TestNode::start(&[]);
    b.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{}", a.p2p_port.unwrap())), json!("onetry")]);
    common::poll_until(
        || b.rpc_ok("getbestblockhash", vec![]) == tip,
        test_timeout(60),
        "B never synced from A",
    );

    let before = allocated(&a);
    let out = strip(&a, &hash).expect("strip");
    assert_eq!(out["outcome"], "stripped", "{out}");
    assert!(!payload_on_disk(&a), "premise: the payload is gone");
    assert!(allocated(&a) < before, "premise: the punch gave space back");
    assert_raw_block_unavailable(&a, &hash);
    let stripped = allocated(&a);

    let peer = a.rpc_ok("getpeerinfo", vec![])[0]["id"].clone();
    a.rpc_ok("getblockfrompeer", vec![json!(hash), peer]);
    common::poll_until(
        || a.rpc_call_with_params("getblock", vec![json!(hash), json!(0)]).unwrap()["result"] == raw,
        test_timeout(30),
        "the block was never restored",
    );
    let block = a.rpc_ok("getblock", vec![json!(hash), json!(1)]);
    assert!(block.get("opreturn_stripped").is_none(), "the record is gone: {block}");
    assert!(payload_on_disk(&a), "the payload is back on disk");
    assert!(allocated(&a) > stripped, "the punched space is allocated again");
    assert!(!has_corrupt_warning(&a));

    // In place: a restart reads it intact, and a strip finds no record to redo.
    let datadir = a.datadir.clone();
    let rpcport = a.rpcport;
    a.stop();
    a.datadir = PathBuf::new();
    let mut a = TestNode::start_with_datadir(&datadir, rpcport, &["--allowteststrip", "--blocksxor=1"]);
    assert_eq!(a.rpc_ok("getblock", vec![json!(hash), json!(0)]), raw);
    a.stop();
    b.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Restoring the last stripped block with the option off (plan §11.5) makes
/// the node a full node again without a restart: it advertises
/// `NODE_NETWORK`, a peer that connects afterwards sees it in the node's
/// `version`, and the strip family is gone from the datadir, so it would open
/// as an ordinary one.
#[test]
fn restoring_the_last_stripped_block_makes_a_full_node_again() {
    use serde_json::json;

    let network = |node: &TestNode| {
        node.rpc_ok("getnetworkinfo", vec![])["localservicesnames"].as_array().unwrap().contains(&json!("NETWORK"))
    };
    let mut a = TestNode::start(&["--allowteststrip"]);
    let hash = block_with_a_big_op_return(&a);
    let raw = a.rpc_ok("getblock", vec![json!(hash), json!(0)]);
    let tip = a.rpc_ok("getbestblockhash", vec![]);
    let mut b = TestNode::start(&[]);
    b.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{}", a.p2p_port.unwrap())), json!("onetry")]);
    common::poll_until(|| b.rpc_ok("getbestblockhash", vec![]) == tip, test_timeout(60), "B never synced from A");
    assert_eq!(strip(&a, &hash).expect("strip")["outcome"], "stripped");

    // A restart with the option off: the stripped block keeps A limited, and
    // the worker runs to notice when it goes.
    let (datadir, rpcport) = (a.datadir.clone(), a.rpcport);
    a.stop();
    a.datadir = PathBuf::new();
    let a_port = find_available_port();
    let port_arg = format!("--port={a_port}");
    let mut a = TestNode::start_with_datadir(&datadir, rpcport, &[&port_arg]);
    assert!(!network(&a), "premise: limited while a block is stripped");
    a.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{}", b.p2p_port.unwrap())), json!("onetry")]);
    // Until a peer has finished its handshake, `getblockfrompeer` refuses it.
    common::poll_until(
        || {
            a.rpc_ok("getpeerinfo", vec![]).as_array().unwrap().iter().any(|p| {
                a.rpc_call_with_params("getblockfrompeer", vec![json!(hash), p["id"].clone()]).unwrap()["error"]
                    .is_null()
            })
        },
        test_timeout(30),
        "A never asked B for the block",
    );
    common::poll_until(
        || a.rpc_call_with_params("getblock", vec![json!(hash), json!(0)]).unwrap()["result"] == raw,
        test_timeout(30),
        "the block was never restored",
    );
    // A new tip wakes the worker from its idle wait.
    let addr = DeterministicWallet::from_secret([0x5b; 32]).address.to_string();
    mine(&a, 1, &addr);
    common::poll_until(|| network(&a), test_timeout(60), "A never advertised NODE_NETWORK again");
    assert_eq!(a.rpc_ok("getopreturnpruneinfo", vec![])["blocks"], 0);

    let mut c = TestNode::start(&[]);
    c.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{a_port}")), json!("onetry")]);
    common::poll_until(
        || {
            c.rpc_ok("getpeerinfo", vec![])
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["servicesnames"].as_array().unwrap().contains(&json!("NETWORK")))
        },
        test_timeout(30),
        "a new peer never saw NODE_NETWORK in A's version",
    );
    c.stop();
    b.stop();

    a.stop();
    a.datadir = PathBuf::new();
    let cfs = rocksdb::DB::list_cf(&rocksdb::Options::default(), datadir.join("regtest").join("chainstate")).unwrap();
    assert!(!cfs.iter().any(|n| n == "opreturn_strip"), "the strip family is gone: {cfs:?}");
    let mut a = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    assert!(network(&a), "a full node after a restart");
    assert_eq!(a.rpc_ok("getblock", vec![json!(hash), json!(0)]), raw);
    a.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// A transaction paying `wallet` back with one OP_RETURN of `len` bytes (the
/// whole scriptPubKey), spending coinbase `coinbase`. Returns its txid.
fn send_op_return(node: &TestNode, wallet: &DeterministicWallet, coinbase: u64, len: usize, byte: u8) -> String {
    use bitcoin::blockdata::opcodes::all::OP_RETURN;
    use bitcoin::script::{Builder, PushBytesBuf};

    // OP_RETURN, the push opcode and its length bytes, then the data.
    let header = match len {
        0..=77 => 2,
        78..=258 => 3,
        259..=65538 => 4,
        _ => 6,
    };
    let data = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(PushBytesBuf::try_from(vec![byte; len - header]).unwrap())
        .into_script();
    assert_eq!(data.len(), len, "premise: the script is {len} bytes");
    let (raw, txid) = common::build_signed_p2wpkh_spend_of_coinbases(
        node,
        &[(coinbase, wallet)],
        &[wallet.address.script_pubkey(), data],
        100_000,
    );
    node.rpc_ok(
        "sendrawtransaction",
        vec![serde_json::json!(raw), serde_json::json!(0.1), serde_json::json!(50)],
    );
    txid
}

fn wait_for_the_worker(node: &TestNode, below: u64) -> serde_json::Value {
    common::poll_until(
        || node.rpc_ok("getopreturnpruneinfo", vec![])["examined_below_height"].as_u64().unwrap_or(0) >= below,
        test_timeout(120),
        "the strip worker never examined the chain",
    );
    node.rpc_ok("getopreturnpruneinfo", vec![])
}

/// `getrawtransaction <txid>`'s whole response.
fn raw_tx(node: &TestNode, txid: &str) -> serde_json::Value {
    node.rpc_call_with_params("getrawtransaction", vec![serde_json::json!(txid)]).unwrap()
}

/// `-pruneopreturn` end to end (plan PR 8): the worker strips what is deep and
/// large enough, the surfaces read it through its records, the node advertises
/// only `NODE_NETWORK_LIMITED`, and the state survives restarts: with the
/// option on, with it off (still limited, still reported), and with a lower
/// threshold (newly eligible outputs stripped on the rescan).
#[test]
fn pruneopreturn_strips_deep_large_payloads_end_to_end() {
    use serde_json::json;

    let rpcport = find_available_port();
    let datadir = fresh_test_datadir("satd-pruneopreturn-e2e");
    let on: &[&str] = &["--pruneopreturn=288", "--pruneopreturnsize=1000", "--txindex"];
    // The chain is built with the option off, so the block files' allocated
    // size can be taken before anything is stripped; then it is turned on.
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--txindex"]);
    let wallet = DeterministicWallet::from_secret([0x64; 32]);
    let addr = wallet.address.to_string();
    mine(&node, 110, &addr);
    // 1 KB, 10 KB and 90 KB payloads, stripped; 500 bytes, kept until the
    // threshold drops; 80 bytes, never stripped.
    let big = [
        send_op_return(&node, &wallet, 1, 1_000, 0x51),
        send_op_return(&node, &wallet, 2, 10_000, 0x52),
        send_op_return(&node, &wallet, 3, 90_000, 0x53),
    ];
    let medium = send_op_return(&node, &wallet, 4, 500, 0x54);
    let small = send_op_return(&node, &wallet, 5, 80, 0x55);
    let block = mine(&node, 1, &addr).remove(0);
    let height = node.rpc_ok("getblockheader", vec![json!(block)])["height"].as_u64().unwrap();
    let raw_before = node.rpc_ok("getblock", vec![json!(block), json!(0)]);
    assert_eq!(
        node.rpc_ok("getblock", vec![json!(block), json!(1)])["tx"].as_array().unwrap().len(),
        6,
        "premise: all five are in one block"
    );
    // Deep enough: more than 288 + 2 below the tip.
    mine(&node, 300, &addr);
    assert!(
        node.rpc_ok("getnetworkinfo", vec![])["localservicesnames"].as_array().unwrap().contains(&json!("NETWORK")),
        "premise: a full node before the option"
    );
    let allocated_before = allocated(&node);
    node.stop();
    node.datadir = PathBuf::new();
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, on);

    let info = wait_for_the_worker(&node, height + 1);
    assert_eq!(info["enabled"], true, "{info}");
    assert_eq!(info["depth"], 288);
    assert_eq!(info["min_size"], 1000);
    assert_eq!(info["probe"], "ok", "{info}");
    assert_eq!(info["blocks"], 1, "{info}");
    assert_eq!(info["transactions"], 3, "{info}");
    assert_eq!(info["outputs"], 3, "{info}");
    assert_eq!(info["bytes_zeroed"], 101_000 - 3, "{info}");
    let freed = info["bytes_freed_estimate"].as_u64().unwrap();
    assert!(freed >= 90_000 - 2 * 4096, "{info}");
    assert!(
        info["blocks_dir_allocated_bytes"].as_u64().unwrap() + freed <= allocated_before,
        "the punches gave back at least the estimate: {info} (before: {allocated_before})"
    );
    let chain = node.rpc_ok("getblockchaininfo", vec![]);
    assert_eq!(chain["pruned"], false, "-prune's field keeps its meaning");
    assert_eq!(chain["opreturn_prune"]["blocks"], 1, "{chain}");

    // The surfaces: the large ones are stripped, the small ones intact.
    for txid in &big {
        assert_eq!(raw_tx(&node, txid)["error"]["message"], "Transaction data not available (OP_RETURN data stripped)");
        let verbose = node.rpc_ok("getrawtransaction", vec![json!(txid), json!(1)]);
        assert_eq!(verbose["opreturn_stripped"], true, "{verbose}");
    }
    for txid in [&medium, &small] {
        assert!(raw_tx(&node, txid)["result"].is_string(), "{txid} is intact");
    }
    assert_raw_block_unavailable(&node, &block);
    let services = node.rpc_ok("getnetworkinfo", vec![])["localservicesnames"].clone();
    assert!(!services.as_array().unwrap().contains(&json!("NETWORK")), "{services}");
    assert!(services.as_array().unwrap().contains(&json!("NETWORK_LIMITED")), "{services}");
    assert!(!has_corrupt_warning(&node));
    node.stop();
    node.datadir = PathBuf::new();

    // A restart keeps it all.
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, on);
    let again = node.rpc_ok("getopreturnpruneinfo", vec![]);
    assert_eq!((again["blocks"].clone(), again["bytes_zeroed"].clone()), (json!(1), json!(101_000 - 3)));
    assert_raw_block_unavailable(&node, &block);
    node.stop();
    node.datadir = PathBuf::new();

    // Off: nothing is restored, the node stays limited, and it still reports.
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--txindex"]);
    let chain = node.rpc_ok("getblockchaininfo", vec![]);
    assert_eq!(chain["opreturn_prune"]["enabled"], false, "{chain}");
    assert_eq!(chain["opreturn_prune"]["blocks"], 1, "{chain}");
    let services = node.rpc_ok("getnetworkinfo", vec![])["localservicesnames"].clone();
    assert!(!services.as_array().unwrap().contains(&json!("NETWORK")), "still limited: {services}");
    assert_raw_block_unavailable(&node, &block);
    node.stop();
    node.datadir = PathBuf::new();

    // A lower threshold: the 500-byte output is stripped on the rescan; the
    // 80-byte one never is.
    let lower: &[&str] = &["--pruneopreturn=288", "--pruneopreturnsize=400", "--txindex"];
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, lower);
    common::poll_until(
        || node.rpc_ok("getopreturnpruneinfo", vec![])["transactions"] == json!(4),
        test_timeout(120),
        "the rescan never stripped the newly eligible output",
    );
    assert_eq!(
        raw_tx(&node, &medium)["error"]["message"],
        "Transaction data not available (OP_RETURN data stripped)"
    );
    assert!(raw_tx(&node, &small)["result"].is_string(), "the 80-byte one is never stripped");
    assert_ne!(node.rpc_call_with_params("getblock", vec![json!(block), json!(0)]).unwrap()["result"], raw_before);
    assert!(!has_corrupt_warning(&node));
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// A raw inbound peer, read on the test's own thread.
struct RawPeer {
    stream: std::net::TcpStream,
}

impl RawPeer {
    fn connect(port: u16) -> Self {
        Self::connect_as(port, bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS)
    }

    /// Connect advertising `services`.
    fn connect_as(port: u16, services: bitcoin::p2p::ServiceFlags) -> Self {
        use bitcoin::p2p::message::NetworkMessage;
        let stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.set_nodelay(true).unwrap();
        let mut peer = Self { stream };
        let zero: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        peer.send(NetworkMessage::Version(bitcoin::p2p::message_network::VersionMessage {
            version: 70016,
            services,
            timestamp: 1_760_000_000,
            receiver: bitcoin::p2p::Address::new(&zero, bitcoin::p2p::ServiceFlags::NONE),
            sender: bitcoin::p2p::Address::new(&zero, services),
            nonce: 0x5a5a_0001,
            user_agent: "/opreturn-strip-test/".into(),
            start_height: 0,
            relay: false,
        }));
        let mut got_version = false;
        loop {
            match peer.recv(Duration::from_secs(30)) {
                Ok(NetworkMessage::Version(_)) => got_version = true,
                Ok(NetworkMessage::Verack) if got_version => break,
                Ok(_) => {}
                Err(e) => panic!("handshake: {e}"),
            }
        }
        peer.send(NetworkMessage::Verack);
        peer
    }

    fn send(&mut self, msg: bitcoin::p2p::message::NetworkMessage) {
        use std::io::Write;
        let raw = bitcoin::p2p::message::RawNetworkMessage::new(bitcoin::p2p::Magic::REGTEST, msg);
        let _ = self.stream.write_all(&bitcoin::consensus::serialize(&raw));
    }

    fn recv(&mut self, timeout: Duration) -> std::io::Result<bitcoin::p2p::message::NetworkMessage> {
        use std::io::Read;
        self.stream.set_read_timeout(Some(timeout)).unwrap();
        let mut header = [0u8; 24];
        self.stream.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut buf = header.to_vec();
        buf.resize(24 + len, 0);
        self.stream.read_exact(&mut buf[24..])?;
        let raw: bitcoin::p2p::message::RawNetworkMessage = bitcoin::consensus::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(raw.into_payload())
    }

    /// How many blocks the node invs for a `getblocks` from genesis. A
    /// `getheaders` sent after it, which the node always answers, marks where
    /// its answer ends (a ping would not: the connection answers it first).
    fn getblocks_from_genesis(&mut self) -> usize {
        use bitcoin::hashes::Hash;
        use bitcoin::p2p::message::NetworkMessage;
        use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
        let zero = bitcoin::BlockHash::all_zeros();
        self.send(NetworkMessage::GetBlocks(GetBlocksMessage::new(vec![genesis], zero)));
        self.send(NetworkMessage::GetHeaders(GetHeadersMessage::new(vec![genesis], zero)));
        let mut blocks = 0;
        loop {
            match self.recv(Duration::from_secs(30)).expect("an answer") {
                NetworkMessage::Inv(inv) => blocks += inv.iter().filter(|i| matches!(i, Inventory::Block(_))).count(),
                NetworkMessage::Headers(_) => return blocks,
                NetworkMessage::Ping(n) => self.send(NetworkMessage::Pong(n)),
                _ => {}
            }
        }
    }

    /// The node's answer to a `getdata` for `hash`: the block, `notfound`, or
    /// `None` when it closed the connection. Pings are answered on the way.
    fn get_block(&mut self, hash: bitcoin::BlockHash) -> Option<Result<bitcoin::Block, ()>> {
        use bitcoin::p2p::message::NetworkMessage;
        use bitcoin::p2p::message_blockdata::Inventory;
        self.send(NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]));
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match self.recv(left) {
                Ok(NetworkMessage::Block(b)) if b.block_hash() == hash => return Some(Ok(b)),
                Ok(NetworkMessage::NotFound(inv)) if inv.iter().any(|i| i == &Inventory::WitnessBlock(hash)) => {
                    return Some(Err(()));
                }
                Ok(NetworkMessage::Ping(n)) => self.send(NetworkMessage::Pong(n)),
                Ok(_) => {}
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                    panic!("no answer for {hash}")
                }
                Err(_) => return None,
            }
        }
    }
}

/// `-pruneopreturnpeers` (plan §2.9.1). Under `intact` a peer gets an intact
/// block at depth 500, `notfound` for a stripped one at about the same depth,
/// and stays connected; the node advertises `NODE_NETWORK_LIMITED` and
/// `NODE_INTACT_BLOCKS`, never `NODE_NETWORK`. Under `limited`, the default,
/// the same request for the intact block disconnects the peer, as a pruned
/// Core node does, and `getblocks` invs no deep block.
#[test]
fn pruneopreturnpeers_intact_serves_deep_intact_blocks_and_notfound_for_stripped() {
    use serde_json::json;

    for intact in [true, false] {
        let mut args = vec!["--pruneopreturn=288"];
        if intact {
            args.push("--pruneopreturnpeers=intact");
        }
        let mut node = TestNode::start(&args);
        let stripped = block_with_a_big_op_return(&node);
        let height = node.rpc_ok("getblockheader", vec![json!(stripped)])["height"].as_u64().unwrap();
        let addr = DeterministicWallet::from_secret([0x65; 32]).address.to_string();
        mine(&node, 500, &addr);
        common::poll_until(
            || node.rpc_ok("getopreturnpruneinfo", vec![])["blocks"] == json!(1),
            test_timeout(120),
            "the worker never stripped the block",
        );
        let deep: bitcoin::BlockHash =
            node.rpc_ok("getblockhash", vec![json!(height + 1)]).as_str().unwrap().parse().unwrap();

        let services = u64::from_str_radix(
            node.rpc_ok("getnetworkinfo", vec![])["localservices"].as_str().unwrap(),
            16,
        )
        .unwrap();
        assert_eq!(services & 1, 0, "never NODE_NETWORK");
        assert_ne!(services & (1 << 10), 0, "NODE_NETWORK_LIMITED");
        assert_eq!(services & (1 << 28) != 0, intact, "NODE_INTACT_BLOCKS only under intact");

        let mut peer = RawPeer::connect(node.p2p_port.unwrap());
        // `getblocks` invs only what the node would serve.
        assert_eq!(peer.getblocks_from_genesis(), if intact { 500 } else { 0 });
        if intact {
            let got = peer.get_block(deep).expect("still connected");
            assert_eq!(got.expect("the intact block").block_hash(), deep);
            let stripped: bitcoin::BlockHash = stripped.parse().unwrap();
            assert_eq!(peer.get_block(stripped), Some(Err(())), "notfound, and the peer stays");
            assert!(peer.get_block(deep).is_some_and(|b| b.is_ok()), "still served after the notfound");
        } else {
            assert_eq!(peer.get_block(deep), None, "a limited node disconnects a deep request");
        }
        node.stop();
    }
}

/// What a [`RawPeer`] serving a restore does with a `getdata` for a block.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Withhold {
    /// Never answers: the request stalls.
    Silently,
    /// Answers `notfound`.
    NotFound,
}

type Asked = std::sync::Arc<std::sync::Mutex<Vec<bitcoin::BlockHash>>>;

/// Run `peer` on a thread of its own until `stop`: answer pings, and treat
/// every block `getdata` as `mode` says. Returns the blocks asked for, as
/// they are asked.
fn withhold_blocks(
    mut peer: RawPeer,
    mode: Withhold,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> (std::thread::JoinHandle<()>, Asked) {
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::p2p::message_blockdata::Inventory;
    let asked = Asked::default();
    let seen = asked.clone();
    let thread = std::thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            match peer.recv(Duration::from_millis(200)) {
                Ok(NetworkMessage::Ping(n)) => peer.send(NetworkMessage::Pong(n)),
                Ok(NetworkMessage::GetData(inv)) => {
                    let blocks: Vec<Inventory> =
                        inv.into_iter().filter(|i| matches!(i, Inventory::Block(_) | Inventory::WitnessBlock(_))).collect();
                    seen.lock().unwrap().extend(blocks.iter().filter_map(|i| match i {
                        Inventory::Block(h) | Inventory::WitnessBlock(h) => Some(*h),
                        _ => None,
                    }));
                    if mode == Withhold::NotFound && !blocks.is_empty() {
                        peer.send(NetworkMessage::NotFound(blocks));
                    }
                }
                Ok(_) => {}
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
        }
    });
    (thread, asked)
}

/// `n` blocks with a big OP_RETURN on a node that strips them, and an archive
/// node B that synced the chain from it first. A is stopped when this
/// returns. Returns A's datadir and RPC port, each stripped block's hash and
/// raw bytes, and B.
fn stripped_node_and_archive(n: usize, extra: &[&str]) -> (PathBuf, u16, Vec<(String, serde_json::Value)>, TestNode) {
    use serde_json::json;
    let mut args = vec!["--allowteststrip"];
    args.extend_from_slice(extra);
    let mut a = TestNode::start(&args);
    let hashes: Vec<String> = (0..n).map(|_| block_with_a_big_op_return(&a)).collect();
    let blocks: Vec<(String, serde_json::Value)> =
        hashes.iter().map(|h| (h.clone(), a.rpc_ok("getblock", vec![json!(h), json!(0)]))).collect();
    let tip = a.rpc_ok("getbestblockhash", vec![]);
    let b = TestNode::start(&[]);
    b.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{}", a.p2p_port.unwrap())), json!("onetry")]);
    common::poll_until(|| b.rpc_ok("getbestblockhash", vec![]) == tip, test_timeout(120), "B never synced from A");
    for (hash, _) in &blocks {
        assert_eq!(strip(&a, hash).expect("strip")["outcome"], "stripped");
    }
    assert_eq!(a.rpc_ok("getopreturnpruneinfo", vec![])["blocks"], json!(n));
    let (datadir, rpcport) = (a.datadir.clone(), a.rpcport);
    a.stop();
    a.datadir = PathBuf::new();
    (datadir, rpcport, blocks, b)
}

fn advertises_network(node: &TestNode) -> bool {
    node.rpc_ok("getnetworkinfo", vec![])["localservicesnames"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("NETWORK"))
}

fn prune_info(node: &TestNode) -> serde_json::Value {
    node.rpc_ok("getopreturnpruneinfo", vec![])
}

/// Wait for a `-restoreopreturns` node to restore every stripped block in
/// `blocks`, then for the finish: a block mined to wake the worker, and the
/// node reports `restored` and advertises `NODE_NETWORK`.
fn wait_for_the_restore(node: &TestNode, blocks: &[(String, serde_json::Value)], secs: u64) {
    use serde_json::json;
    common::poll_until(
        || blocks.iter().all(|(h, raw)| node.rpc_call_with_params("getblock", vec![json!(h), json!(0)]).unwrap()["result"] == *raw),
        test_timeout(secs),
        "the stripped blocks were never all restored",
    );
    let addr = DeterministicWallet::from_secret([0x5b; 32]).address.to_string();
    mine(node, 1, &addr);
    common::poll_until(
        || prune_info(node)["worker"] == "restored" && advertises_network(node),
        test_timeout(90),
        "the node never finished the restore",
    );
}

/// Plan §11.7 tests 1 and 2: a node restarted with `-restoreopreturns` and an
/// archive peer downloads every stripped block again, gets the original
/// bytes back and the punched space with them, and becomes a full node
/// without a restart: it advertises `NODE_NETWORK` and serves a new peer the
/// whole chain. Its datadir is left with no strip family, so it runs as an
/// ordinary node without the flag.
#[test]
fn restoreopreturns_downloads_every_stripped_block_again() {
    use serde_json::json;
    let (datadir, rpcport, blocks, mut b) = stripped_node_and_archive(3, &[]);

    let a_port = find_available_port();
    let port_arg = format!("--port={a_port}");
    let mut a = TestNode::start_with_datadir(&datadir, rpcport, &["--restoreopreturns", &port_arg]);
    assert!(!advertises_network(&a), "premise: limited while blocks are stripped");
    let info = prune_info(&a);
    assert_eq!(info["enabled"], false, "{info}");
    assert_eq!(info["worker"], "waiting_for_peers", "no peer yet: {info}");
    let stripped_allocation = allocated(&a);

    a.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{}", b.p2p_port.unwrap())), json!("onetry")]);
    wait_for_the_restore(&a, &blocks, 120);
    let info = prune_info(&a);
    assert_eq!(info["blocks"], 0, "{info}");
    assert_eq!(info["restore"]["total_blocks"], 3, "{info}");
    assert_eq!(info["restore"]["restored_blocks"], 3, "{info}");
    assert_eq!(info["restore"]["remaining_blocks"], 0, "{info}");
    assert!(info["restore"]["bytes_downloaded"].as_u64().unwrap() > 3 * PAYLOAD as u64, "{info}");
    assert!(payload_on_disk(&a), "the payloads are back on disk");
    assert!(allocated(&a) > stripped_allocation, "the punched space is allocated again");
    assert!(!has_corrupt_warning(&a));
    for (hash, _) in &blocks {
        let block = a.rpc_ok("getblock", vec![json!(hash), json!(2)]);
        let ours = a.rpc_ok("getblock", vec![json!(hash), json!(0)]);
        assert_eq!(ours, b.rpc_ok("getblock", vec![json!(hash), json!(0)]), "the archive's bytes");
        assert!(block.get("opreturn_stripped").is_none(), "{hash}");
        let txid = block["tx"][1]["txid"].as_str().unwrap();
        assert!(a.rpc_call_with_params("getrawtransaction", vec![json!(txid), json!(0), json!(hash)]).unwrap()["result"].is_string());
    }
    b.stop();

    // A new peer sees NODE_NETWORK and syncs the whole chain from A alone,
    // blocks far deeper than 288 included.
    let tip = a.rpc_ok("getbestblockhash", vec![]);
    let c = TestNode::start(&[]);
    c.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{a_port}")), json!("onetry")]);
    common::poll_until(|| c.rpc_ok("getbestblockhash", vec![]) == tip, test_timeout(120), "C never synced from A");
    let a_seen = c.rpc_ok("getpeerinfo", vec![]);
    assert!(a_seen[0]["servicesnames"].as_array().unwrap().contains(&json!("NETWORK")), "{a_seen}");
    let mut c = c;
    c.stop();

    a.stop();
    a.datadir = PathBuf::new();
    let cfs = rocksdb::DB::list_cf(&rocksdb::Options::default(), datadir.join("regtest").join("chainstate")).unwrap();
    assert!(!cfs.iter().any(|n| n == "opreturn_strip"), "the strip family is gone: {cfs:?}");
    // Without the flag: an ordinary unpruned node.
    let mut a = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    assert!(advertises_network(&a), "a full node after a restart");
    assert_eq!(prune_info(&a)["worker"], "off");
    a.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Plan §11.7 test 4: the flag on a datadir that never stripped starts, and
/// creates no strip family.
#[test]
fn restoreopreturns_on_a_node_that_never_stripped_does_nothing() {
    let rpcport = find_available_port();
    let datadir = fresh_test_datadir("satd-restore-never-stripped");
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--restoreopreturns"]);
    let addr = DeterministicWallet::from_secret([0x5b; 32]).address.to_string();
    mine(&node, 5, &addr);
    assert!(advertises_network(&node));
    let info = prune_info(&node);
    assert_eq!(info["worker"], "restored", "{info}");
    assert_eq!(info["restore"]["remaining_blocks"], 0, "{info}");
    node.stop();
    node.datadir = PathBuf::new();
    let cfs = rocksdb::DB::list_cf(&rocksdb::Options::default(), datadir.join("regtest").join("chainstate")).unwrap();
    assert!(!cfs.iter().any(|n| n == "opreturn_strip"), "{cfs:?}");
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Plan §11.7 test 3 at startup: the flag with an OP_RETURN pruning option
/// fails, naming both. The must-succeed half is every other restore test.
#[test]
fn restoreopreturns_with_a_pruning_option_is_refused_at_startup() {
    let datadir = fresh_test_datadir("satd-restore-conflict");
    let stderr = datadir.join("stderr.log");
    let _ = std::fs::create_dir_all(&datadir);
    let status = Command::new(env!("CARGO_BIN_EXE_satd"))
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", find_available_port()))
        .arg(format!("--port={}", find_available_port()))
        .arg("--restoreopreturns")
        .arg("--pruneopreturn=0")
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .status()
        .expect("run satd");
    let text = std::fs::read_to_string(&stderr).unwrap_or_default();
    assert!(!status.success(), "refused at startup: {text}");
    assert!(text.contains("-restoreopreturns") && text.contains("-pruneopreturn"), "{text}");
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Plan §11.7 test 5: with only a limited peer connected, an intact one
/// included, the restore waits for a full peer and asks the limited one for
/// nothing. Connecting the archive peer unblocks it.
#[test]
fn restoreopreturns_never_asks_a_limited_peer() {
    use bitcoin::p2p::ServiceFlags;
    use serde_json::json;
    let (datadir, rpcport, blocks, mut b) = stripped_node_and_archive(1, &[]);
    let a_port = find_available_port();
    let port_arg = format!("--port={a_port}");
    let mut a = TestNode::start_with_datadir(&datadir, rpcport, &["--restoreopreturns", &port_arg]);

    let intact = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS | ServiceFlags::from(1u64 << 28);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (limited, asked) = withhold_blocks(RawPeer::connect_as(a_port, intact), Withhold::NotFound, stop.clone());
    common::poll_until(
        || a.rpc_ok("getpeerinfo", vec![]).as_array().unwrap().len() == 1,
        test_timeout(30),
        "the limited peer never connected",
    );
    // Several of the download's two-second ticks.
    std::thread::sleep(Duration::from_secs(8));
    let info = prune_info(&a);
    assert_eq!(info["worker"], "waiting_for_peers", "{info}");
    assert_eq!(info["restore"]["peers"], 0, "{info}");

    a.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{}", b.p2p_port.unwrap())), json!("onetry")]);
    wait_for_the_restore(&a, &blocks, 120);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    limited.join().unwrap();
    assert_eq!(*asked.lock().unwrap(), Vec::<bitcoin::BlockHash>::new(), "the limited peer was never asked");
    a.stop();
    b.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Plan §11.7 tests 6 and 7: a full peer that withholds its blocks, by never
/// answering or by answering `notfound`, is asked first; the restore moves
/// the blocks to the archive peer once it connects, and completes.
#[test]
fn restoreopreturns_moves_on_from_a_peer_that_withholds_blocks() {
    use serde_json::json;
    for mode in [Withhold::NotFound, Withhold::Silently] {
        let (datadir, rpcport, blocks, mut b) = stripped_node_and_archive(2, &[]);
        let a_port = find_available_port();
        let port_arg = format!("--port={a_port}");
        let mut a = TestNode::start_with_datadir(&datadir, rpcport, &["--restoreopreturns", &port_arg]);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (withholding, asked) = withhold_blocks(RawPeer::connect(a_port), mode, stop.clone());
        common::poll_until(|| asked.lock().unwrap().len() >= blocks.len(), test_timeout(30), "the withholding peer was never asked");
        a.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{}", b.p2p_port.unwrap())), json!("onetry")]);
        // A stalled request moves after the 15-second stall timeout.
        wait_for_the_restore(&a, &blocks, 120);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        withholding.join().unwrap();
        let asked = asked.lock().unwrap();
        for (hash, _) in &blocks {
            assert!(asked.contains(&hash.parse().unwrap()), "the withholding peer was asked for {hash}");
        }
        a.stop();
        b.stop();
        let _ = std::fs::remove_dir_all(&datadir);
    }
}

/// Plan §11.7 test 9: with too little free space for what the holes lack,
/// the restore waits; with enough, it resumes and completes.
#[test]
fn restoreopreturns_waits_for_free_space() {
    use serde_json::json;
    let (datadir, rpcport, blocks, mut b) = stripped_node_and_archive(1, &[]);
    let free = datadir.join("free-space");
    std::fs::write(&free, "0").unwrap();
    let mut a = TestNode::start_with_datadir_env(
        &datadir,
        rpcport,
        &["--restoreopreturns"],
        &[("SATD_TEST_FREE_SPACE_FILE", free.to_str().unwrap())],
    );
    a.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{}", b.p2p_port.unwrap())), json!("onetry")]);
    common::poll_until(|| prune_info(&a)["worker"] == "waiting_for_disk", test_timeout(30), "never waited for disk");
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(prune_info(&a)["worker"], "waiting_for_disk");
    assert_eq!(prune_info(&a)["blocks"], 1, "nothing restored while waiting");
    std::fs::write(&free, (1u64 << 40).to_string()).unwrap();
    wait_for_the_restore(&a, &blocks, 120);
    a.stop();
    b.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Plan §11.7 test 10: a pruning node restores its stripped blocks and ends
/// with none, still pruning.
#[test]
fn restoreopreturns_on_a_pruning_node() {
    use serde_json::json;
    let (datadir, rpcport, blocks, mut b) = stripped_node_and_archive(2, &[]);
    let mut a = TestNode::start_with_datadir(&datadir, rpcport, &["--restoreopreturns", "--prune=1"]);
    a.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{}", b.p2p_port.unwrap())), json!("onetry")]);
    common::poll_until(
        || prune_info(&a)["blocks"] == 0,
        test_timeout(120),
        "the stripped blocks were never all restored",
    );
    for (hash, raw) in &blocks {
        assert_eq!(a.rpc_ok("getblock", vec![json!(hash), json!(0)]), *raw);
    }
    let addr = DeterministicWallet::from_secret([0x5b; 32]).address.to_string();
    mine(&a, 1, &addr);
    common::poll_until(|| prune_info(&a)["worker"] == "restored", test_timeout(90), "never finished");
    assert_eq!(a.rpc_ok("getblockchaininfo", vec![])["pruned"], true, "still pruning");
    assert!(!advertises_network(&a), "a pruning node stays limited");
    a.stop();
    b.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}
