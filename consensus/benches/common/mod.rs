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
pub enum Category {
    /// Legacy pre-SegWit: no WITNESS, no TAPROOT.
    Legacy,
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
    } else {
        Category::Legacy
    }
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
