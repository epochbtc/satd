//! What a hostile PSBT can make the verifier do.
//!
//! `analyzepsbt` is a read-capability method, so this is attacker-controlled
//! input on a listener an operator may expose more widely than the wallet one.
//! The expensive part is BIP 374 verification, and the number of proofs to
//! check is (eligible inputs) x (scan keys with a per-input share) — a product,
//! not a sum. This measures the worst shape that fits in a plausible PSBT and
//! pins the bound.

mod common;

use std::time::Instant;

use bitcoin::hashes::{Hash, hash160};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Amount, ScriptBuf, TxOut};
use satd_psbt::raw::{RawMap, RawPair, RawPsbt};
use satd_psbt::{V2View, keys, sp};

/// Inputs and scan keys for the shape below. The product is what costs, and
/// 60 x 60 is 3600 units — under the cap, so the measurement is of work that
/// actually happens.
const INPUTS: usize = 60;
const SCAN_KEYS: usize = 60;

/// A PSBT with `INPUTS` eligible inputs and `SCAN_KEYS` silent payment outputs
/// under distinct scan keys, every input carrying a share and a proof for every
/// scan key. Proofs are junk: verification costs the same whether it succeeds
/// or fails, and generating real ones would only make the test slow.
fn expensive_psbt() -> RawPsbt {
    let secp = Secp256k1::new();

    let mut global = RawMap::new();
    global.set(RawPair::new(keys::global::VERSION, Vec::new(), 2u32.to_le_bytes().to_vec()));
    global.set(RawPair::new(keys::global::TX_VERSION, Vec::new(), 2u32.to_le_bytes().to_vec()));
    let mut count = Vec::new();
    satd_psbt::raw::write_compact_size(&mut count, INPUTS as u64);
    global.set(RawPair::new(keys::global::INPUT_COUNT, Vec::new(), count));
    let mut count = Vec::new();
    satd_psbt::raw::write_compact_size(&mut count, SCAN_KEYS as u64);
    global.set(RawPair::new(keys::global::OUTPUT_COUNT, Vec::new(), count));

    let scan_keys: Vec<PublicKey> = (0..SCAN_KEYS)
        .map(|i| {
            let mut secret = [1u8; 32];
            secret[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secret).expect("a secret"))
        })
        .collect();

    let mut inputs = Vec::with_capacity(INPUTS);
    for i in 0..INPUTS {
        let mut secret = [2u8; 32];
        secret[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        let secret = SecretKey::from_slice(&secret).expect("a secret");
        let key = PublicKey::from_secret_key(&secp, &secret);
        let script = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
            hash160::Hash::hash(&key.serialize()).to_byte_array(),
        ));

        let mut map = RawMap::new();
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&(i as u64).to_be_bytes());
        map.set(RawPair::new(keys::input::PREVIOUS_TXID, Vec::new(), txid.to_vec()));
        map.set(RawPair::new(
            keys::input::OUTPUT_INDEX,
            Vec::new(),
            0u32.to_le_bytes().to_vec(),
        ));
        map.set(RawPair::new(
            keys::input::WITNESS_UTXO,
            Vec::new(),
            bitcoin::consensus::serialize(&TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: script,
            }),
        ));
        map.set(RawPair::new(
            keys::input::BIP32_DERIVATION,
            key.serialize().to_vec(),
            vec![0u8; 4],
        ));
        for scan in &scan_keys {
            map.set(RawPair::new(
                keys::input::SP_ECDH_SHARE,
                scan.serialize().to_vec(),
                key.serialize().to_vec(),
            ));
            map.set(RawPair::new(
                keys::input::SP_DLEQ,
                scan.serialize().to_vec(),
                vec![0x11u8; 64],
            ));
        }
        inputs.push(map);
    }

    let spend = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
    let outputs = scan_keys
        .iter()
        .map(|scan| {
            let mut map = RawMap::new();
            map.set(RawPair::new(
                keys::output::AMOUNT,
                Vec::new(),
                1_000i64.to_le_bytes().to_vec(),
            ));
            let mut info = scan.serialize().to_vec();
            info.extend_from_slice(&spend.serialize());
            map.set(RawPair::new(keys::output::SP_V0_INFO, Vec::new(), info));
            map
        })
        .collect();

    RawPsbt {
        global,
        inputs,
        outputs,
    }
}

/// The measurement. This is not a performance test — it is the number that
/// decides whether a cap is needed, recorded where it can be re-measured.
#[test]
fn the_expensive_shape_stays_within_its_budget() {
    let raw = expensive_psbt();
    let size = raw.serialize().len();
    let view = V2View::new(&raw).expect("a version 2 PSBT");

    let started = Instant::now();
    let report = sp::verify(&view, None).expect("verifies");
    let elapsed = started.elapsed();

    let proofs = INPUTS * SCAN_KEYS;
    let per_proof = elapsed.as_secs_f64() / proofs as f64;
    println!(
        "{INPUTS} inputs x {SCAN_KEYS} scan keys = {proofs} proofs over {size} bytes \
         in {elapsed:?} ({:.0} us per proof, {:.1} ms per KiB of PSBT)",
        per_proof * 1e6,
        elapsed.as_secs_f64() * 1000.0 / (size as f64 / 1024.0),
    );

    // Every output is refused, since the proofs are junk — which is also what
    // makes this the worst case: a failing proof costs exactly what a passing
    // one does, so nothing short-circuits.
    assert!(report.outputs.iter().all(|o| o.status != sp::OutputStatus::Ready));

    // The work is linear in the number of share-proof pairs the PSBT carries,
    // and a pair costs about a hundred bytes, so the cost is linear in the
    // PSBT's size. A debug build is roughly thirty times slower than a release
    // one, so the budget here is generous on purpose: what it guards against
    // is a change that makes the cost super-linear, not a slow machine.
    assert!(
        elapsed.as_secs_f64() < 30.0,
        "verification took {elapsed:?} for {proofs} proofs over {size} bytes; \
         if this is a constant-factor regression raise the budget, and if the \
         cost has stopped being linear in the number of share-proof pairs, \
         cap them"
    );
}

/// Past the cap, the verifier refuses before doing any of the work rather than
/// after. A PSBT that fits inside the 20 MiB request limit can ask for tens of
/// seconds of curve arithmetic otherwise, on a read-capability method.
#[test]
fn past_the_cap_the_work_is_refused_before_it_starts() {
    let mut raw = expensive_psbt();
    // Triple the inputs: 180 x 60 is 10800 units, past the 10000 cap.
    let extra = raw.inputs.clone();
    raw.inputs.extend(extra.clone());
    raw.inputs.extend(extra);
    let mut count = Vec::new();
    satd_psbt::raw::write_compact_size(&mut count, raw.inputs.len() as u64);
    raw.global.set(RawPair::new(keys::global::INPUT_COUNT, Vec::new(), count));
    for (i, map) in raw.inputs.iter_mut().enumerate().skip(INPUTS) {
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&(i as u64 + 1000).to_be_bytes());
        map.set(RawPair::new(keys::input::PREVIOUS_TXID, Vec::new(), txid.to_vec()));
    }

    let view = V2View::new(&raw).expect("a version 2 PSBT");
    let started = Instant::now();
    let refused = sp::verify(&view, None);
    let elapsed = started.elapsed();

    match refused {
        Err(satd_psbt::PsbtError::TooMuchWork { limit }) => {
            assert_eq!(limit, sp::MAX_CURVE_OPERATIONS)
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // Counting is cheap; the point of the cap is that it happens first.
    assert!(
        elapsed.as_millis() < 500,
        "the refusal took {elapsed:?}, which means work was done before the count"
    );
}

/// Doubling the inputs doubles the work, rather than quadrupling it: the cost
/// is linear in the share-proof pairs a PSBT actually carries. That linearity
/// is what makes a single cap on the count a sufficient bound.
#[test]
fn the_cost_is_linear_in_the_pairs_the_psbt_carries() {
    // Half the scan keys, so that doubling the inputs stays under the cap.
    let mut small = expensive_psbt();
    small.outputs.truncate(SCAN_KEYS / 2);
    let mut count = Vec::new();
    satd_psbt::raw::write_compact_size(&mut count, small.outputs.len() as u64);
    small.global.set(RawPair::new(keys::global::OUTPUT_COUNT, Vec::new(), count));

    let mut large = small.clone();
    // Twice the inputs, the same scan keys: twice the pairs.
    let extra = large.inputs.clone();
    large.inputs.extend(extra);
    let mut count = Vec::new();
    satd_psbt::raw::write_compact_size(&mut count, large.inputs.len() as u64);
    large.global.set(RawPair::new(keys::global::INPUT_COUNT, Vec::new(), count));
    // Distinct outpoints, so the doubled inputs are genuinely separate.
    for (i, map) in large.inputs.iter_mut().enumerate().skip(INPUTS) {
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&(i as u64 + 1000).to_be_bytes());
        map.set(RawPair::new(keys::input::PREVIOUS_TXID, Vec::new(), txid.to_vec()));
    }

    let time = |raw: &RawPsbt| {
        let view = V2View::new(raw).expect("a version 2 PSBT");
        let started = Instant::now();
        let _ = sp::verify(&view, None).expect("verifies");
        started.elapsed().as_secs_f64()
    };
    // Warm the code paths so the first measurement is not paying for them.
    let _ = time(&small);
    let one = time(&small);
    let two = time(&large);

    println!("{INPUTS} inputs: {one:.3}s, {} inputs: {two:.3}s", INPUTS * 2);
    assert!(
        two < one * 3.0,
        "doubling the inputs took {two:.3}s against {one:.3}s; the cost should roughly \
         double, and anything near a quadrupling means the work has stopped being \
         linear in the share-proof pairs"
    );
}
