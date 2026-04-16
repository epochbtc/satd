//! Shared benchmark fixtures for consensus Rust-vs-C++ perf comparison.
//!
//! Loads Bitcoin Core test vectors once and shapes them into WorkloadCase
//! structs that are cheap to feed into both verifiers.
//!
//! NOTE: this file lives under `benches/common/` (not `benches/common.rs`)
//! so Cargo does not try to compile it as its own bench target.

#![allow(dead_code)] // Not every bench uses every helper.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use serde_json::Value;

// Reuse the maintained parse_flags / parse_script helpers from the test
// harness rather than duplicating the opcode table.
#[allow(unused_imports, dead_code)]
#[path = "../../tests/helpers.rs"]
mod helpers;
use helpers::{parse_flags, parse_script};

/// A prepared benchmark case: everything needed to call
/// `verify_with_flags` on either engine, with no per-iter allocation.
pub struct WorkloadCase {
    pub name: String,
    /// The spent output's script_pubkey.
    pub script_pubkey: Vec<u8>,
    /// The spent output's amount in sats (matters for BIP143).
    pub amount: u64,
    /// Fully-serialized spending transaction.
    pub tx_bytes: Vec<u8>,
    /// Input index in the spending tx (always 0 for synthetic workloads).
    pub input_index: usize,
    /// Flags to pass to verify_with_flags.
    pub flags: u32,
    /// Prev outputs required for taproot (spk, value). Empty for non-taproot.
    pub prev_outputs: Vec<(Vec<u8>, u64)>,
}

/// The flags bitcoinconsensus recognises — it rejects unknown flag bits.
pub const CPP_RECOGNIZED_FLAGS: u32 = bitcoinconsensus::VERIFY_P2SH
    | bitcoinconsensus::VERIFY_DERSIG
    | bitcoinconsensus::VERIFY_NULLDUMMY
    | bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY
    | bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY
    | bitcoinconsensus::VERIFY_WITNESS
    | bitcoinconsensus::VERIFY_TAPROOT;

pub fn cpp_safe_flags(f: u32) -> u32 {
    f & CPP_RECOGNIZED_FLAGS
}

/// Verify with the Rust consensus engine.
#[inline]
pub fn verify_rust(c: &WorkloadCase) -> bool {
    let result = if c.prev_outputs.is_empty() {
        consensus::verify_with_flags(
            &c.script_pubkey,
            c.amount,
            &c.tx_bytes,
            None,
            c.input_index,
            c.flags,
        )
    } else {
        let utxos: Vec<consensus::Utxo> = c
            .prev_outputs
            .iter()
            .map(|(spk, val)| consensus::Utxo {
                script_pubkey: spk.as_ptr(),
                script_pubkey_len: spk.len() as u32,
                value: *val as i64,
            })
            .collect();
        consensus::verify_with_flags(
            &c.script_pubkey,
            c.amount,
            &c.tx_bytes,
            Some(&utxos),
            c.input_index,
            c.flags,
        )
    };
    result.is_ok()
}

/// Verify with the C++ bitcoinconsensus FFI.
#[inline]
pub fn verify_cpp(c: &WorkloadCase) -> bool {
    let result = if c.prev_outputs.is_empty() {
        bitcoinconsensus::verify_with_flags(
            &c.script_pubkey,
            c.amount,
            &c.tx_bytes,
            None,
            c.input_index,
            c.flags,
        )
    } else {
        let utxos: Vec<bitcoinconsensus::Utxo> = c
            .prev_outputs
            .iter()
            .map(|(spk, val)| bitcoinconsensus::Utxo {
                script_pubkey: spk.as_ptr(),
                script_pubkey_len: spk.len() as u32,
                value: *val as i64,
            })
            .collect();
        bitcoinconsensus::verify_with_flags(
            &c.script_pubkey,
            c.amount,
            &c.tx_bytes,
            Some(&utxos),
            c.input_index,
            c.flags,
        )
    };
    result.is_ok()
}

fn build_crediting_tx(script_pubkey: &[u8], value: u64) -> Transaction {
    Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
        }],
    }
}

fn build_spending_tx(
    script_sig: &[u8],
    witness: &[Vec<u8>],
    credit_tx: &Transaction,
) -> Transaction {
    let mut buf = Vec::new();
    credit_tx.consensus_encode(&mut buf).unwrap();
    let txid = Txid::from_byte_array(
        bitcoin::hashes::sha256d::Hash::hash(&buf).to_byte_array(),
    );
    let mut w = Witness::new();
    for item in witness {
        w.push(item);
    }
    Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
            sequence: Sequence::MAX,
            witness: w,
        }],
        output: vec![TxOut {
            value: credit_tx.output[0].value,
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn serialize_tx(tx: &Transaction) -> Vec<u8> {
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf).unwrap();
    buf
}

/// Which script-complexity category a case belongs to, based on its flags.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Category {
    /// Bare pre-SegWit scripts: no P2SH, no WITNESS, no TAPROOT.
    Legacy,
    /// P2SH-wrapped legacy scripts (no WITNESS).
    P2sh,
    /// SegWit v0 or native witness program.
    SegwitV0,
    /// Taproot (v1 witness).
    Taproot,
}

pub fn categorize(flags: u32) -> Category {
    if flags & consensus::flags::VERIFY_TAPROOT != 0 {
        Category::Taproot
    } else if flags & consensus::flags::VERIFY_WITNESS != 0 {
        Category::SegwitV0
    } else if flags & consensus::flags::VERIFY_P2SH != 0 {
        Category::P2sh
    } else {
        Category::Legacy
    }
}

/// Run a Rust-vs-C++ comparison bench over a workload, reporting throughput
/// in elements/sec. Both functions iterate over the full workload per sample
/// so the number maps directly to verify-rate on the IBD hot path.
pub fn run_suite(c: &mut criterion::Criterion, group_name: &str, workload: &[WorkloadCase]) {
    eprintln!("{group_name}: {} cases", workload.len());
    let mut group = c.benchmark_group(group_name);
    group.throughput(criterion::Throughput::Elements(workload.len() as u64));

    group.bench_function("rust", |b| {
        b.iter(|| {
            for case in workload {
                let _ = std::hint::black_box(verify_rust(case));
            }
        })
    });

    group.bench_function("cpp", |b| {
        b.iter(|| {
            for case in workload {
                let _ = std::hint::black_box(verify_cpp(case));
            }
        })
    });

    group.finish();
}

/// Filter a workload by category.
pub fn filter_category(cases: Vec<WorkloadCase>, target: Category) -> Vec<WorkloadCase> {
    cases
        .into_iter()
        .filter(|c| categorize(c.flags) == target)
        .collect()
}

/// Parse script_tests.json into WorkloadCase values that BOTH engines accept
/// (skips comment rows, skips tx-builder failures, skips mismatched cases).
pub fn load_script_tests() -> Vec<WorkloadCase> {
    let data = include_str!("../../test-data/script_tests.json");
    let tests: Vec<Value> = serde_json::from_str(data).unwrap();
    let mut cases = Vec::new();

    for test in &tests {
        if test.is_string() {
            continue;
        }
        let arr = match test.as_array() {
            Some(a) => a,
            None => continue,
        };

        let (witness_items, script_sig_str, script_pubkey_str, flags_str, n_value): (
            Vec<Vec<u8>>,
            &str,
            &str,
            &str,
            u64,
        ) = if arr[0].is_array() {
            if arr.len() < 5 {
                continue;
            }
            let wit_arr = arr[0].as_array().unwrap();
            let spk_str = arr[2].as_str().unwrap();
            if spk_str.contains("#TAPROOTOUTPUT#") || spk_str.contains("#CONTROLBLOCK#") {
                continue;
            }
            let amount = wit_arr
                .last()
                .and_then(|v| v.as_f64())
                .map(|v| (v * 1e8) as u64)
                .unwrap_or(0);
            let mut has_special = false;
            let wit: Vec<Vec<u8>> = wit_arr[..wit_arr.len() - 1]
                .iter()
                .map(|v| {
                    let s = v.as_str().unwrap();
                    if s.starts_with('#') {
                        has_special = true;
                        Vec::new()
                    } else {
                        hex::decode(s).unwrap_or_default()
                    }
                })
                .collect();
            if has_special {
                continue;
            }
            (
                wit,
                arr[1].as_str().unwrap(),
                spk_str,
                arr[3].as_str().unwrap(),
                amount,
            )
        } else {
            if arr.len() < 4 || !arr[0].is_string() {
                continue;
            }
            (
                Vec::new(),
                arr[0].as_str().unwrap(),
                arr[1].as_str().unwrap(),
                arr[2].as_str().unwrap(),
                0u64,
            )
        };

        let mut script_flags = parse_flags(flags_str);
        if script_flags & consensus::flags::VERIFY_CLEANSTACK != 0 {
            script_flags |= consensus::flags::VERIFY_P2SH | consensus::flags::VERIFY_WITNESS;
        }
        let safe_flags = cpp_safe_flags(script_flags);

        let script_sig = parse_script(script_sig_str);
        let script_pubkey = parse_script(script_pubkey_str);

        let credit_tx = build_crediting_tx(&script_pubkey, n_value);
        let spend_tx = build_spending_tx(&script_sig, &witness_items, &credit_tx);
        let tx_bytes = serialize_tx(&spend_tx);

        let label = format!(
            "{} => {}",
            shorten(script_sig_str, 40),
            shorten(script_pubkey_str, 40)
        );

        let prev_outputs = if safe_flags & bitcoinconsensus::VERIFY_TAPROOT != 0 {
            vec![(script_pubkey.clone(), n_value)]
        } else {
            Vec::new()
        };

        let case = WorkloadCase {
            name: label,
            script_pubkey,
            amount: n_value,
            tx_bytes,
            input_index: 0,
            flags: safe_flags,
            prev_outputs,
        };

        // Only keep cases both engines accept — apples-to-apples bench.
        if verify_rust(&case) && verify_cpp(&case) {
            cases.push(case);
        }
    }

    cases
}

fn shorten(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

// ---------------------------------------------------------------------------
// Real mainnet block — JSON fixture extracted from the synced node via
// bench-data/extract_block.py. One WorkloadCase per (tx, input) pair across
// every non-coinbase tx in the block. This is the most honest approximation
// of IBD hot-path workload: real tx graphs, real scripts, real sizes.
// ---------------------------------------------------------------------------

/// Load a real-block fixture. Returns (height, cases).
pub fn load_real_block(fixture_json: &str) -> (u32, Vec<WorkloadCase>) {
    use bitcoin::consensus::Decodable;

    let fixture: Value = serde_json::from_str(fixture_json).unwrap();
    let height = fixture["height"].as_u64().unwrap() as u32;
    let block_hex = fixture["block_hex"].as_str().unwrap();
    let prevouts_map = fixture["prevouts"].as_object().unwrap();

    let block_bytes = hex::decode(block_hex).unwrap();
    let block: bitcoin::Block =
        bitcoin::Block::consensus_decode(&mut block_bytes.as_slice()).unwrap();

    // Flag sets to try: pick the widest set both engines accept for each
    // input. In practice bitcoinconsensus applies a consistent mainnet flag
    // vector, but older blocks may fail modern flags like NULLDUMMY.
    // Start permissive; fall back if the engines disagree.
    let candidate_flags = [
        CPP_RECOGNIZED_FLAGS, // everything the C++ engine knows
        bitcoinconsensus::VERIFY_P2SH
            | bitcoinconsensus::VERIFY_WITNESS
            | bitcoinconsensus::VERIFY_TAPROOT,
        bitcoinconsensus::VERIFY_P2SH | bitcoinconsensus::VERIFY_WITNESS,
        bitcoinconsensus::VERIFY_P2SH,
        0,
    ];

    let mut cases = Vec::new();
    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        if tx.is_coinbase() {
            continue;
        }
        let mut tx_bytes = Vec::new();
        tx.consensus_encode(&mut tx_bytes).unwrap();

        // Assemble prev_outputs aligned to input order — needed for taproot.
        let prev_outputs: Vec<(Vec<u8>, u64)> = tx
            .input
            .iter()
            .map(|inp| {
                let key = format!(
                    "{}:{}",
                    inp.previous_output.txid, inp.previous_output.vout
                );
                let entry = &prevouts_map[&key];
                let spk = hex::decode(entry["spk"].as_str().unwrap()).unwrap();
                let value = entry["value"].as_u64().unwrap();
                (spk, value)
            })
            .collect();

        for (i, inp) in tx.input.iter().enumerate() {
            let key = format!(
                "{}:{}",
                inp.previous_output.txid, inp.previous_output.vout
            );
            let entry = match prevouts_map.get(&key) {
                Some(e) => e,
                None => continue,
            };
            let spk = hex::decode(entry["spk"].as_str().unwrap()).unwrap();
            let amount = entry["value"].as_u64().unwrap();

            // Probe for the widest flag set that both engines accept.
            let mut chosen_flags: Option<u32> = None;
            for &flags in &candidate_flags {
                let has_taproot = flags & bitcoinconsensus::VERIFY_TAPROOT != 0;
                let test = WorkloadCase {
                    name: String::new(),
                    script_pubkey: spk.clone(),
                    amount,
                    tx_bytes: tx_bytes.clone(),
                    input_index: i,
                    flags,
                    prev_outputs: if has_taproot {
                        prev_outputs.clone()
                    } else {
                        Vec::new()
                    },
                };
                if verify_rust(&test) && verify_cpp(&test) {
                    chosen_flags = Some(flags);
                    break;
                }
            }
            let flags = match chosen_flags {
                Some(f) => f,
                None => continue, // neither engine accepts this input — skip
            };

            let has_taproot = flags & bitcoinconsensus::VERIFY_TAPROOT != 0;
            cases.push(WorkloadCase {
                name: format!("h{height}_tx{tx_idx}_in{i}"),
                script_pubkey: spk,
                amount,
                tx_bytes: tx_bytes.clone(),
                input_index: i,
                flags,
                prev_outputs: if has_taproot {
                    prev_outputs.clone()
                } else {
                    Vec::new()
                },
            });
        }
    }

    (height, cases)
}

// ---------------------------------------------------------------------------
// bip341_wallet_vectors.json — BIP341 key-path spending test vector. One
// fully-signed tx with 9 taproot key-path inputs. Small sample but the only
// taproot workload we have in-tree.
// ---------------------------------------------------------------------------

pub fn load_bip341_keypath_cases() -> Vec<WorkloadCase> {
    let data = include_str!("../../test-data/bip341_wallet_vectors.json");
    let vectors: Value = serde_json::from_str(data).unwrap();
    let kps = &vectors["keyPathSpending"][0];

    let tx_hex = kps["auxiliary"]["fullySignedTx"].as_str().unwrap();
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let utxos_json = kps["given"]["utxosSpent"].as_array().unwrap();
    let prevs: Vec<(Vec<u8>, u64)> = utxos_json
        .iter()
        .map(|u| {
            let spk = hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap();
            let amount = u["amountSats"].as_u64().unwrap();
            (spk, amount)
        })
        .collect();

    let flags = bitcoinconsensus::VERIFY_P2SH
        | bitcoinconsensus::VERIFY_WITNESS
        | bitcoinconsensus::VERIFY_TAPROOT;

    let mut cases = Vec::new();
    for (i, prev) in prevs.iter().enumerate() {
        let case = WorkloadCase {
            name: format!("bip341_keypath#{i}"),
            script_pubkey: prev.0.clone(),
            amount: prev.1,
            tx_bytes: tx_bytes.clone(),
            input_index: i,
            flags,
            prev_outputs: prevs.clone(),
        };
        if verify_rust(&case) && verify_cpp(&case) {
            cases.push(case);
        }
    }
    cases
}

// ---------------------------------------------------------------------------
// tx_valid.json — real Bitcoin transactions with multiple inputs. Each test
// entry becomes N WorkloadCases (one per input). This is the closest thing
// to "real IBD workload" we have in-tree.
// ---------------------------------------------------------------------------

fn fill_flags(mut f: u32) -> u32 {
    if f & consensus::flags::VERIFY_CLEANSTACK != 0 {
        f |= consensus::flags::VERIFY_WITNESS;
    }
    if f & consensus::flags::VERIFY_WITNESS != 0 {
        f |= consensus::flags::VERIFY_P2SH;
    }
    f
}

pub fn load_tx_valid_cases() -> Vec<WorkloadCase> {
    use bitcoin::consensus::Decodable;
    use std::collections::HashMap;

    let data = include_str!("../../test-data/tx_valid.json");
    let tests: Vec<Value> = serde_json::from_str(data).unwrap();
    let mut cases = Vec::new();

    for test in &tests {
        let arr = match test.as_array() {
            Some(a) if a.len() == 3 && a[0].is_array() => a,
            _ => continue,
        };
        let inputs = arr[0].as_array().unwrap();
        let tx_hex = match arr[1].as_str() {
            Some(s) => s,
            None => continue,
        };
        let flags_str = match arr[2].as_str() {
            Some(s) => s,
            None => continue,
        };

        // Build prevout maps keyed by (txid, vout).
        let mut script_map: HashMap<(Txid, u32), Vec<u8>> = HashMap::new();
        let mut value_map: HashMap<(Txid, u32), u64> = HashMap::new();
        let mut ok = true;
        for input in inputs {
            let a = match input.as_array() {
                Some(a) if a.len() >= 3 && a.len() <= 4 => a,
                _ => {
                    ok = false;
                    break;
                }
            };
            let txid_hex = match a[0].as_str() {
                Some(s) => s,
                None => {
                    ok = false;
                    break;
                }
            };
            let txid_bytes = match hex::decode(txid_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => {
                    ok = false;
                    break;
                }
            };
            // tx_valid.json uses big-endian txid display — reverse for internal form.
            let mut txid_arr = [0u8; 32];
            for (i, b) in txid_bytes.iter().enumerate() {
                txid_arr[31 - i] = *b;
            }
            let txid = Txid::from_byte_array(txid_arr);
            let vout = match a[1].as_u64() {
                Some(v) => v as u32,
                None => {
                    ok = false;
                    break;
                }
            };
            let spk = parse_script(a[2].as_str().unwrap_or(""));
            script_map.insert((txid, vout), spk);
            if a.len() >= 4 {
                value_map.insert((txid, vout), a[3].as_i64().unwrap_or(0) as u64);
            }
        }
        if !ok {
            continue;
        }

        let tx_bytes = match hex::decode(tx_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let tx: Transaction = match Transaction::consensus_decode(&mut tx_bytes.as_slice()) {
            Ok(t) => t,
            Err(_) => continue,
        };

        let excluded = parse_flags(flags_str);
        let verify_flags = fill_flags(!excluded & consensus::flags::ALL_FLAGS);
        let safe_flags = cpp_safe_flags(verify_flags);
        let has_taproot = safe_flags & bitcoinconsensus::VERIFY_TAPROOT != 0;

        // Build prev_outputs for the whole tx (required for taproot sighash).
        let prev_outputs: Vec<(Vec<u8>, u64)> = tx
            .input
            .iter()
            .map(|inp| {
                let key = (inp.previous_output.txid, inp.previous_output.vout);
                (
                    script_map.get(&key).cloned().unwrap_or_default(),
                    value_map.get(&key).copied().unwrap_or(0),
                )
            })
            .collect();

        let tx_label = format!("tx_{}", shorten(tx_hex, 16));

        for (i, inp) in tx.input.iter().enumerate() {
            let key = (inp.previous_output.txid, inp.previous_output.vout);
            let spk = match script_map.get(&key) {
                Some(s) => s.clone(),
                None => continue,
            };
            let amount = value_map.get(&key).copied().unwrap_or(0);

            let case = WorkloadCase {
                name: format!("{tx_label}#{i}"),
                script_pubkey: spk,
                amount,
                tx_bytes: tx_bytes.clone(),
                input_index: i,
                flags: safe_flags,
                prev_outputs: if has_taproot {
                    prev_outputs.clone()
                } else {
                    Vec::new()
                },
            };
            if verify_rust(&case) && verify_cpp(&case) {
                cases.push(case);
            }
        }
    }

    cases
}
