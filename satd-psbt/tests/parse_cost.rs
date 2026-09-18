//! What it costs to parse a map with a great many pairs.
//!
//! Every PSBT surface parses attacker-controlled bytes before it knows what
//! version it is looking at, and BIP 174 lets a map hold any number of pairs.
//! A map's duplicate-key rule is the only part of parsing that has to compare
//! a pair against the ones before it, so it is the only part that could be
//! quadratic — and a single map inside the 20 MiB request limit holds over a
//! million pairs, which at a linear scan each is tens of minutes of CPU for
//! one request.

use std::time::Instant;

use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, absolute, transaction};
use satd_psbt::raw::RawPsbt;

/// Every length in this file is below 0xfd, so a compact size is one byte.
fn write_compact_size(out: &mut Vec<u8>, v: u64) {
    assert!(v < 0xfd, "this helper only writes one-byte compact sizes");
    out.push(v as u8);
}

/// A version 0 PSBT whose global map carries `pairs` distinct unknown pairs
/// on top of the unsigned transaction it needs to be well formed.
fn psbt_with_pairs(pairs: usize) -> Vec<u8> {
    let tx = bitcoin::consensus::serialize(&Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::new(),
        }],
    });

    let mut out = b"psbt\xff".to_vec();
    // PSBT_GLOBAL_UNSIGNED_TX.
    write_compact_size(&mut out, 1);
    out.push(0x00);
    write_compact_size(&mut out, tx.len() as u64);
    out.extend_from_slice(&tx);

    for i in 0..pairs {
        // Key type 0xfc (proprietary, and unknown to us) plus an eight-byte
        // counter, so that every key is distinct and none is a duplicate.
        // Duplicates are what the check is looking for; distinct keys are the
        // expensive case, since each one is compared against all of its
        // predecessors before being accepted.
        let key_data = (i as u64).to_be_bytes();
        write_compact_size(&mut out, 1 + key_data.len() as u64);
        out.push(0xfc);
        out.extend_from_slice(&key_data);
        write_compact_size(&mut out, 0);
    }
    out.push(0x00);
    // The input map and the output map the transaction above calls for, each
    // empty.
    out.push(0x00);
    out.push(0x00);
    out
}

/// A big map parses in time proportional to its size, not to the square of
/// its pair count.
///
/// The numbers matter: with a linear scan per pair, 200,000 pairs is about
/// twenty billion byte comparisons — minutes. With a set beside the map it is
/// a fraction of a second. The budget below is two orders of magnitude above
/// the latter and two below the former, so it is not a timing test in any
/// meaningful sense: a slow runner cannot fail it, and a quadratic check
/// cannot pass it.
#[test]
fn a_map_with_many_pairs_parses_in_linear_time() {
    const PAIRS: usize = 200_000;

    let bytes = psbt_with_pairs(PAIRS);
    let started = Instant::now();
    let psbt = RawPsbt::parse(&bytes).expect("a well formed PSBT");
    let elapsed = started.elapsed();

    println!(
        "{PAIRS} pairs over {} bytes parsed in {elapsed:?}",
        bytes.len()
    );
    // The unsigned transaction plus the unknown pairs.
    assert_eq!(psbt.global.len(), PAIRS + 1);
    assert_eq!(psbt.serialize(), bytes, "parsing stays lossless");

    assert!(
        elapsed.as_secs_f64() < 10.0,
        "parsing {PAIRS} pairs took {elapsed:?}; a per-pair scan of the pairs \
         already read makes this quadratic, and a map that large fits inside \
         the request limit several times over"
    );
}

/// The check still refuses a duplicate, which is the whole reason it exists.
#[test]
fn a_duplicate_key_in_a_big_map_is_still_refused() {
    const PAIRS: usize = 10_000;

    let bytes = psbt_with_pairs(PAIRS);
    // Repeat the very first unknown pair at the end, where only something
    // that remembers every key it has seen will catch it. The map ends with
    // its separator, so the repeat goes just before that.
    let first = {
        let mut pair = Vec::new();
        write_compact_size(&mut pair, 9);
        pair.push(0xfc);
        pair.extend_from_slice(&0u64.to_be_bytes());
        write_compact_size(&mut pair, 0);
        pair
    };
    let global_end = bytes.len() - 3;
    let mut with_duplicate = bytes[..global_end].to_vec();
    with_duplicate.extend_from_slice(&first);
    with_duplicate.extend_from_slice(&bytes[global_end..]);

    match RawPsbt::parse(&with_duplicate) {
        Err(satd_psbt::PsbtError::DuplicateKey { key_type, .. }) => assert_eq!(key_type, 0xfc),
        other => panic!("expected a duplicate key refusal, got {other:?}"),
    }
}
