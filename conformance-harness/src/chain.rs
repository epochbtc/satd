//! The chain operations of PROTOCOL.md (sections 4.8 to 4.13), answered by
//! the node's own `ChainState` on a RocksDB store in a temporary directory,
//! verifying scripts with the Rust engine.
//!
//! The regtest activation-height overrides are process-wide and set once, as
//! the daemon sets them at startup, so every `chain_reset` gets a process of
//! its own: the harness starts itself again with `--chain-worker` and passes
//! the chain operations to it until the next reset ([`Worker`]).
//!
//! A block or header goes through what the node does with one from the same
//! source, not through Core's rules restated here:
//!
//! - `via: p2p` blocks pass the peer manager's gates first, in its order: the
//!   mutation check when the parent is known, then a block whose parent is
//!   unknown waits for it if it was requested (the node's orphan buffer) and
//!   is dropped otherwise. The node does not treat an unrequested block with a
//!   known parent differently, and has no low-work drop, so neither does this.
//! - `via: rpc` blocks get `submitblock`'s proof-of-work check first.
//! - Headers go to `accept_headers` (a `headers` message) or `accept_header`
//!   (`submitheader`).
//!
//! After every event the best stored chain is activated, as the node's block
//! processor does on each wakeup.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::str::FromStr;
use std::time::Instant;

use bitcoin::consensus::deserialize;
use bitcoin::{Block, BlockHash, Network};
use node::chain::state::{AssumeValid, ChainError, ChainState};
use node::net::orphan_blocks::OrphanBlocks;
use node::storage::blockindex::BlockStatus;
use node::validation::script::{self, TestActivationOverrides};
use node::validation::ValidationError;
use serde_json::{json, Value};

use crate::{bad_request, field_hex, Fail, Fields};

/// The operations a [`Worker`] answers.
pub const OPS: &[&str] = &[
    "chain_reset",
    "chain_process_block",
    "chain_process_headers",
    "chain_invalidate",
    "chain_tip",
    "chain_tips",
    "utxo_hash",
];

/// The child process holding the chain of the last `chain_reset`.
pub struct Worker {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl Worker {
    pub fn spawn() -> Result<Worker, Fail> {
        let exe = std::env::current_exe().map_err(|e| internal(format!("locating the harness: {e}")))?;
        let mut child = Command::new(exe)
            .arg("--chain-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| internal(format!("starting the chain worker: {e}")))?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        Ok(Worker { child, stdin: Some(stdin), stdout })
    }

    /// Pass one request line on and return the worker's response line.
    pub fn call(&mut self, line: &str) -> Result<Value, Fail> {
        let stdin = self.stdin.as_mut().expect("open until drop");
        writeln!(stdin, "{line}")
            .and_then(|()| stdin.flush())
            .map_err(|e| internal(format!("writing to the chain worker: {e}")))?;
        let mut answer = String::new();
        match self.stdout.read_line(&mut answer) {
            Ok(0) => Err(internal("the chain worker exited")),
            Ok(_) => serde_json::from_str(&answer)
                .map_err(|e| internal(format!("the chain worker answered {answer:?}: {e}"))),
            Err(e) => Err(internal(format!("reading from the chain worker: {e}"))),
        }
    }
}

impl Drop for Worker {
    /// End of input lets the worker exit on its own and remove its data
    /// directory; it is killed only if it has not exited within a few seconds.
    fn drop(&mut self) {
        drop(self.stdin.take());
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn internal(message: impl Into<String>) -> Fail {
    Fail { code: "internal", message: message.into() }
}

/// One chain, from `chain_reset` until the process exits.
pub struct Chain {
    cs: ChainState,
    orphans: OrphanBlocks,
    _dir: tempfile::TempDir,
}

/// The worker's dispatch. `chain` is `None` until the first `chain_reset`.
pub fn dispatch(chain: &mut Option<Chain>, op: &str, req: &Fields) -> Result<Fields, Fail> {
    if op == "chain_reset" {
        if chain.is_some() {
            return Err(internal("a chain worker takes one chain_reset"));
        }
        let (new, genesis) = reset(req)?;
        *chain = Some(new);
        let mut fields = Fields::new();
        fields.insert("genesis".into(), json!(genesis.to_string()));
        return Ok(fields);
    }
    let Some(chain) = chain.as_mut() else {
        return Err(bad_request("no chain_reset yet"));
    };
    match op {
        "chain_process_block" => chain.process_block(req),
        "chain_process_headers" => chain.process_headers(req),
        "chain_invalidate" => chain.invalidate(req),
        "chain_tip" => Ok(chain.tip()),
        "chain_tips" => Ok(chain.tips()),
        "utxo_hash" => chain.utxo_hash(),
        _ => Err(Fail { code: "unsupported_op", message: format!("satd does not answer {op}") }),
    }
}

fn reset(req: &Fields) -> Result<(Chain, BlockHash), Fail> {
    let network = match req.get("network").and_then(Value::as_str) {
        Some("main") => Network::Bitcoin,
        Some("testnet3") => Network::Testnet,
        Some("testnet4") => Network::Testnet4,
        Some("signet") => Network::Signet,
        Some("regtest") => Network::Regtest,
        _ => return Err(bad_request("network must be main, testnet3, testnet4, signet or regtest")),
    };
    let empty = Fields::new();
    let options = match req.get("options") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(o)) => o,
        Some(_) => return Err(bad_request("options must be an object")),
    };
    let mut signet_challenge = None;
    for (key, value) in options {
        match key.as_str() {
            "testactivationheight" => {
                if network != Network::Regtest {
                    return Err(bad_request("testactivationheight is regtest-only"));
                }
                let overrides = activation_overrides(value)?;
                script::set_test_activation_overrides(overrides).map_err(internal)?;
            }
            "test" => {
                let names = value.as_array().ok_or_else(|| bad_request("test must be an array"))?;
                if let Some(name) = names.first() {
                    return Err(Fail {
                        code: "unsupported_op",
                        message: format!("satd has no -test={} option", name.as_str().unwrap_or("?")),
                    });
                }
            }
            "signetchallenge" => {
                if network != Network::Signet {
                    return Err(bad_request("signetchallenge is signet-only"));
                }
                signet_challenge = Some(field_hex(options, "signetchallenge")?);
            }
            other => return Err(bad_request(format!("unknown option {other}"))),
        }
    }

    let dir = tempfile::Builder::new()
        .prefix("satd-conformance-")
        .tempdir()
        .map_err(|e| internal(format!("creating the data directory: {e}")))?;
    let store = node::storage::rocksdb_store::RocksDbStore::open(dir.path(), false, 16, false, 256)
        .map_err(|e| internal(format!("opening the chainstate: {e}")))?;
    let flat_files = node::storage::flatfile::FlatFileManager::new(&dir.path().join("blocks"))
        .map_err(|e| internal(format!("opening the block files: {e}")))?;
    let mut cs = ChainState::new(
        Box::new(store),
        flat_files,
        network,
        Box::new(script::RustVerifier::new(network)),
        AssumeValid::Disabled,
        16,
        2,
        Default::default(),
        Default::default(),
        Default::default(),
    )
    .map_err(|e| internal(format!("creating the chain: {e}")))?;
    cs.set_signet_challenge(signet_challenge);
    let genesis = cs.tip_hash();
    Ok((Chain { cs, orphans: OrphanBlocks::new(), _dir: dir }, genesis))
}

/// Core's `-testactivationheight=name@height`, for the five names it takes.
fn activation_overrides(value: &Value) -> Result<TestActivationOverrides, Fail> {
    let map = value.as_object().ok_or_else(|| bad_request("testactivationheight must be an object"))?;
    let mut o = TestActivationOverrides::default();
    for (name, height) in map {
        let height = height
            .as_u64()
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| bad_request(format!("testactivationheight {name} is not a height")))?;
        let slot = match name.as_str() {
            "bip34" => &mut o.bip34,
            "dersig" => &mut o.dersig,
            "cltv" => &mut o.cltv,
            "csv" => &mut o.csv,
            "segwit" => &mut o.segwit,
            other => return Err(bad_request(format!("unknown deployment {other}"))),
        };
        *slot = Some(height);
    }
    Ok(o)
}

/// The `now` of a request, installed as the node's clock.
fn set_now(req: &Fields, required: bool) -> Result<(), Fail> {
    match req.get("now").and_then(Value::as_u64) {
        Some(now) => {
            // The clock reads 0 as "no mock".
            node::time::set_mock_time(Some(now.max(1)));
            Ok(())
        }
        None if required => Err(bad_request("missing now")),
        None => Ok(()),
    }
}

/// A `via` field: true for `p2p` (the default), false for `rpc`.
fn via_p2p(req: &Fields) -> Result<bool, Fail> {
    match req.get("via").and_then(Value::as_str) {
        None | Some("p2p") => Ok(true),
        Some("rpc") => Ok(false),
        Some(other) => Err(bad_request(format!("unknown via {other}"))),
    }
}

/// How the node's answer to one block or header reads in the protocol.
enum Outcome {
    Accepted,
    Duplicate,
    Orphan,
    Invalid(String),
    Mutated(String),
    Temporary(String),
}

impl Outcome {
    fn into_fields(self, fields: &mut Fields) {
        let (result, reason) = match self {
            Outcome::Accepted => ("accepted", None),
            Outcome::Duplicate => ("duplicate", None),
            Outcome::Orphan => ("orphan", None),
            Outcome::Invalid(r) => ("invalid", Some(r)),
            Outcome::Mutated(r) => ("mutated", Some(r)),
            Outcome::Temporary(r) => ("temporary", Some(r)),
        };
        fields.insert("result".into(), json!(result));
        if let Some(reason) = reason {
            fields.insert("reason".into(), json!(reason));
        }
    }
}

/// The protocol outcome of a `ChainState` refusal, or `Err` for a failure of
/// the node itself rather than a verdict on the block or header.
fn refusal(cs: &ChainState, hash: &BlockHash, e: ChainError) -> Result<Outcome, Fail> {
    Ok(match e {
        ChainError::Duplicate => {
            let invalid = cs.get_block_index(hash).is_some_and(|entry| entry.status == BlockStatus::Invalid);
            if invalid {
                Outcome::Invalid("duplicate-invalid".into())
            } else {
                Outcome::Duplicate
            }
        }
        ChainError::PrevBlockNotFound => Outcome::Orphan,
        ChainError::Validation(ValidationError::TimeTooNew) => Outcome::Temporary(e.to_string()),
        ChainError::Connect(c) if c.is_mutation_class() => Outcome::Mutated(c.to_string()),
        ChainError::Connect(c) if !c.is_verdict_on_block() => {
            return Err(internal(format!("connect failed: {c}")));
        }
        ChainError::BadPrevBlock
        | ChainError::CheckpointMismatch(_)
        | ChainError::ForkBeforeCheckpoint(_)
        | ChainError::Validation(_)
        | ChainError::Connect(_) => Outcome::Invalid(e.to_string()),
        other => return Err(internal(other.to_string())),
    })
}

impl Chain {
    fn process_block(&mut self, req: &Fields) -> Result<Fields, Fail> {
        set_now(req, true)?;
        let p2p = via_p2p(req)?;
        let requested = match req.get("requested") {
            None => true,
            Some(v) => v.as_bool().ok_or_else(|| bad_request("requested must be a bool"))?,
        };
        let bytes = field_hex(req, "block")?;
        let outcome = match deserialize::<Block>(&bytes) {
            Err(e) => Outcome::Mutated(format!("block-decode: {e}")),
            Ok(block) => self.deliver_block(block, p2p, requested)?,
        };
        self.activate();
        let mut fields = Fields::new();
        outcome.into_fields(&mut fields);
        self.insert_tip(&mut fields);
        Ok(fields)
    }

    fn deliver_block(&mut self, block: Block, p2p: bool, requested: bool) -> Result<Outcome, Fail> {
        let hash = block.block_hash();
        let network = self.cs.network;
        if p2p {
            // `PeerManager::reject_if_mutated`, then the block processor's
            // unknown-parent branch (`hold_for_parent`).
            match self.cs.get_block_index(&block.header.prev_blockhash) {
                Some(parent) => {
                    let segwit = node::validation::block::segwit_active_at(network, parent.height + 1);
                    if node::validation::block::is_block_mutated(&block, segwit) {
                        return Ok(Outcome::Mutated("mutated-block".into()));
                    }
                }
                None => {
                    if requested {
                        self.orphans.insert(0, block, network, Instant::now());
                    }
                    return Ok(Outcome::Orphan);
                }
            }
        } else if let Err(e) = node::validation::pow::check_proof_of_work(&block.header) {
            // `submitblock` checks proof of work before anything else.
            return Ok(Outcome::Invalid(e.to_string()));
        }
        match self.cs.accept_block(&block) {
            Ok(_) => {
                self.connect_waiting();
                Ok(Outcome::Accepted)
            }
            Err(e) => refusal(&self.cs, &hash, e),
        }
    }

    /// The block processor's drain of the orphan buffer after an accepted
    /// block: children of the tip, one at a time, until none is left.
    fn connect_waiting(&mut self) {
        while let Some(child) = self.orphans.take_child_of(&self.cs.tip_hash()) {
            match self.cs.accept_block(&child) {
                Ok(acceptance) if acceptance.connected() => {}
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    fn process_headers(&mut self, req: &Fields) -> Result<Fields, Fail> {
        set_now(req, true)?;
        let p2p = via_p2p(req)?;
        let list = req
            .get("headers")
            .and_then(Value::as_array)
            .ok_or_else(|| bad_request("headers must be an array"))?;
        let mut headers = Vec::with_capacity(list.len());
        for h in list {
            let bytes = h
                .as_str()
                .and_then(|s| hex::decode(s).ok())
                .ok_or_else(|| bad_request("headers must be hex strings"))?;
            let header: bitcoin::block::Header =
                deserialize(&bytes).map_err(|e| bad_request(format!("header: {e}")))?;
            headers.push(header);
        }
        // `accept_headers` skips a header it already knows without counting
        // it, so the refused header's position comes from what was known
        // before the call.
        let known_before: Vec<bool> =
            headers.iter().map(|h| self.cs.get_block_index(&h.block_hash()).is_some()).collect();
        let mut fields = Fields::new();
        let (accepted, refused) = if p2p {
            // `PeerManager::handle_headers`.
            if headers.is_empty() {
                (0, None)
            } else {
                self.cs.accept_headers(&headers)
            }
        } else {
            // `submitheader`, one header per request.
            match headers.as_slice() {
                [header] => match self.cs.accept_header(header) {
                    Ok(_) => (1, None),
                    Err(e) => (0, Some(e)),
                },
                _ => return Err(bad_request("via rpc takes one header")),
            }
        };
        let outcome = match refused {
            None | Some(ChainError::Duplicate) => Outcome::Accepted,
            Some(e) => {
                let index = known_before
                    .iter()
                    .enumerate()
                    .filter(|(_, known)| !**known)
                    .nth(accepted as usize)
                    .map(|(i, _)| i)
                    .ok_or_else(|| internal("refused header not found in the request"))?;
                fields.insert("index".into(), json!(index));
                refusal(&self.cs, &headers[index].block_hash(), e)?
            }
        };
        self.activate();
        outcome.into_fields(&mut fields);
        fields.insert("best_header".into(), json!(self.cs.best_header_hash().to_string()));
        Ok(fields)
    }

    fn invalidate(&mut self, req: &Fields) -> Result<Fields, Fail> {
        set_now(req, false)?;
        let hash = req
            .get("hash")
            .and_then(Value::as_str)
            .and_then(|s| BlockHash::from_str(s).ok())
            .ok_or_else(|| bad_request("hash must be a block hash"))?;
        match self.cs.invalidate_block(hash) {
            Ok(()) => {}
            Err(ChainError::BlockNotFound) => return Err(bad_request(format!("unknown block {hash}"))),
            Err(e) => return Err(internal(format!("invalidate_block: {e}"))),
        }
        let mut fields = Fields::new();
        self.insert_tip(&mut fields);
        Ok(fields)
    }

    /// What the block processor does on every wakeup, whatever woke it.
    fn activate(&self) {
        if let Err(e) = self.cs.activate_best_stored_chain() {
            eprintln!("satd-conformance-harness: activating the best stored chain: {e}");
        }
    }

    fn insert_tip(&self, fields: &mut Fields) {
        let (tip, height) = self.cs.tip_snapshot();
        fields.insert("tip".into(), json!(tip.to_string()));
        fields.insert("height".into(), json!(height));
    }

    fn tip(&self) -> Fields {
        let mut fields = Fields::new();
        self.insert_tip(&mut fields);
        let chainwork = self.cs.get_block_index(&self.cs.tip_hash()).map(|e| e.chainwork).unwrap_or([0; 32]);
        fields.insert("chainwork".into(), json!(hex::encode(chainwork)));
        fields
    }

    fn tips(&self) -> Fields {
        let rpc = node::rpc::blockchain::get_chain_tips(&self.cs);
        let tips: Vec<Value> = rpc
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|t| json!({"hash": t["hash"], "height": t["height"], "status": t["status"]}))
                    .collect()
            })
            .unwrap_or_default();
        let mut fields = Fields::new();
        fields.insert("tips".into(), json!(tips));
        fields
    }

    fn utxo_hash(&self) -> Result<Fields, Fail> {
        self.cs.flush_coin_cache().map_err(|e| internal(format!("flushing the coin cache: {e}")))?;
        // `hash_utxo_set`'s pass, counting the coins as it goes so the count
        // and the hash come from the same view.
        let mut hasher = node::storage::compressed_coin::Hs3Hasher::new();
        let mut txouts = 0u64;
        node::storage::Store::for_each_coin_snapshot(self.cs.store_ref().as_ref(), &mut |op, coin| {
            hasher.visit(op, coin);
            txouts += 1;
            Ok(())
        })
        .map_err(|e| internal(format!("reading the UTXO set: {e}")))?;
        let hash = hasher.finalize();
        let mut fields = Fields::new();
        fields.insert("hash_serialized_3".into(), json!(hex::encode(hash)));
        fields.insert("txouts".into(), json!(txouts));
        Ok(fields)
    }
}
