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
    use bitcoin::blockdata::opcodes::all::OP_RETURN;
    use bitcoin::script::{Builder, PushBytesBuf};

    let wallet = DeterministicWallet::from_secret([0x5c; 32]);
    let addr = wallet.address.to_string();
    mine(node, 102, &addr);
    let data = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(PushBytesBuf::try_from(vec![PAYLOAD_BYTE; PAYLOAD - 4]).unwrap())
        .into_script();
    let (stripped_raw, stripped) = common::build_signed_p2wpkh_spend_of_coinbases(
        node,
        &[(1, &wallet)],
        &[wallet.address.script_pubkey(), data],
        100_000,
    );
    let (intact_raw, intact) = common::build_signed_p2wpkh_spend_of_coinbases(
        node,
        &[(2, &wallet)],
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
