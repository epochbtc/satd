//! The test-only `stripopreturns` RPC against a real node: it strips, the
//! strip survives a restart, a kill between the record and the punch leaves
//! a consistent block that the next call finishes, and a corrupt stored copy
//! is refused.

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
/// OP_RETURN, bury it under ten more, and return its hash.
fn block_with_a_big_op_return(node: &TestNode) -> String {
    use bitcoin::blockdata::opcodes::all::OP_RETURN;
    use bitcoin::script::{Builder, PushBytesBuf};

    let wallet = DeterministicWallet::from_secret([0x5b; 32]);
    let addr = wallet.address.to_string();
    mine(node, 101, &addr);
    let data = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(PushBytesBuf::try_from(vec![PAYLOAD_BYTE; PAYLOAD - 4]).unwrap())
        .into_script();
    assert_eq!(data.len(), PAYLOAD);
    let (raw, txid) = common::build_signed_p2wpkh_spend_of_coinbases(
        node,
        &[(1, &wallet)],
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
