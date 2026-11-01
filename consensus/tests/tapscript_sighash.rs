//! The BIP 341 signature message on the script path, against libbitcoinconsensus,
//! and its cost when one input makes many signature checks over a large annex.

mod kernel_ref;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use std::time::{Duration, Instant};

const FLAGS: u32 = consensus::flags::VERIFY_P2SH | consensus::flags::VERIFY_WITNESS | consensus::flags::VERIFY_TAPROOT;
const VALUE: u64 = 100_000;

fn push(data: &[u8]) -> Vec<u8> {
    let mut out = vec![data.len() as u8];
    out.extend_from_slice(data);
    out
}

/// A one-leaf taproot output for `leaf`, and the leaf's control block.
fn taproot_output(leaf: &[u8]) -> (ScriptBuf, Vec<u8>) {
    let secp = Secp256k1::new();
    let internal = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[9; 32]).unwrap()).x_only_public_key().0;
    let leaf = ScriptBuf::from_bytes(leaf.to_vec());
    let info = TaprootBuilder::new().add_leaf(0, leaf.clone()).unwrap().finalize(&secp, internal).unwrap();
    let control = info.control_block(&(leaf, LeafVersion::TapScript)).unwrap().serialize();
    (ScriptBuf::new_p2tr_tweaked(info.output_key()), control)
}

/// A spend of `spks.len()` taproot outputs to two outputs.
fn spend_of(spks: &[ScriptBuf]) -> (Transaction, Vec<TxOut>) {
    let prevouts: Vec<TxOut> =
        spks.iter().map(|spk| TxOut { value: Amount::from_sat(VALUE), script_pubkey: spk.clone() }).collect();
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: (0..spks.len())
            .map(|i| TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([i as u8 + 1; 32]), vout: i as u32 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffff_fffd - i as u32),
                witness: Witness::default(),
            })
            .collect(),
        output: vec![
            TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) },
            TxOut { value: Amount::from_sat(2_000), script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]) },
        ],
    };
    (tx, prevouts)
}

/// rust-bitcoin's BIP 341 script-path signature over input `index`, an
/// implementation independent of the engine's own encoder.
fn sign(tx: &Transaction, prevouts: &[TxOut], index: usize, leaf: &[u8], annex: Option<&[u8]>, codesep: u32, hash_type: TapSighashType) -> Vec<u8> {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32]).unwrap());
    let leaf_hash = bitcoin::TapLeafHash::from_script(bitcoin::Script::from_bytes(leaf), LeafVersion::TapScript);
    let mut engine = bitcoin::TapSighash::engine();
    SighashCache::new(tx)
        .taproot_encode_signing_data_to(
            &mut engine,
            index,
            &Prevouts::All(prevouts),
            annex.map(|a| Annex::new(a).unwrap()),
            Some((leaf_hash, codesep)),
            hash_type,
        )
        .unwrap();
    let sighash = bitcoin::TapSighash::from_engine(engine);
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &kp);
    let mut out = sig.as_ref().to_vec();
    if hash_type != TapSighashType::Default {
        out.push(hash_type as u8);
    }
    out
}

fn xonly() -> [u8; 32] {
    let secp = Secp256k1::new();
    Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32]).unwrap()).x_only_public_key().0.serialize()
}

/// (Rust engine, libbitcoinconsensus) verdicts for input `index`.
fn verify_both(tx: &Transaction, prevouts: &[TxOut], index: usize) -> (bool, bool) {
    let mut bytes = Vec::new();
    tx.consensus_encode(&mut bytes).unwrap();
    let spk = prevouts[index].script_pubkey.as_bytes();
    let rust_utxos: Vec<consensus::Utxo> = prevouts
        .iter()
        .map(|o| consensus::Utxo { script_pubkey: o.script_pubkey.as_bytes().as_ptr(), script_pubkey_len: o.script_pubkey.len() as u32, value: o.value.to_sat() as i64 })
        .collect();
    let cpp_utxos: Vec<kernel_ref::Utxo> = prevouts
        .iter()
        .map(|o| kernel_ref::Utxo { script_pubkey: o.script_pubkey.as_bytes().as_ptr(), script_pubkey_len: o.script_pubkey.len() as u32, value: o.value.to_sat() as i64 })
        .collect();
    let rust = consensus::verify_with_flags(spk, VALUE, &bytes, Some(&rust_utxos), index, FLAGS).is_ok();
    let cpp = kernel_ref::verify_with_flags(spk, VALUE, &bytes, Some(&cpp_utxos), index, FLAGS).is_ok();
    (rust, cpp)
}

/// Every hash type, with and without an annex and an executed
/// OP_CODESEPARATOR, on the second input of two: the engine accepts what
/// Core accepts, and both refuse a signature over a different annex.
#[test]
fn script_path_signatures_match_core_for_every_hash_type() {
    let pk = xonly();
    let mut plain = push(&pk);
    plain.push(0xac); // <pk> OP_CHECKSIG
    let mut with_codesep = vec![0xab]; // OP_CODESEPARATOR <pk> OP_CHECKSIG
    with_codesep.extend(push(&pk));
    with_codesep.push(0xac);
    let hash_types = [
        TapSighashType::Default,
        TapSighashType::All,
        TapSighashType::None,
        TapSighashType::Single,
        TapSighashType::AllPlusAnyoneCanPay,
        TapSighashType::NonePlusAnyoneCanPay,
        TapSighashType::SinglePlusAnyoneCanPay,
    ];
    let annex = [0x50u8, 1, 2, 3];
    let mut cases = 0;
    for (leaf, codesep) in [(&plain, 0xffff_ffffu32), (&with_codesep, 0)] {
        let (spk0, _) = taproot_output(&plain);
        let (spk1, control) = taproot_output(leaf);
        let (mut tx, prevouts) = spend_of(&[spk0, spk1]);
        for hash_type in hash_types {
            for with_annex in [false, true] {
                let a = with_annex.then_some(&annex[..]);
                let sig = sign(&tx, &prevouts, 1, leaf, a, codesep, hash_type);
                let mut w = Witness::new();
                w.push(&sig);
                w.push(leaf);
                w.push(&control);
                if let Some(a) = a {
                    w.push(a);
                }
                tx.input[1].witness = w;
                let label = format!("{hash_type:?} annex={with_annex} codesep={codesep:#x}");
                assert_eq!(verify_both(&tx, &prevouts, 1), (true, true), "{label}");

                // The same signature under a different annex.
                let mut w = tx.input[1].witness.to_vec();
                if with_annex {
                    w.last_mut().unwrap().push(4);
                } else {
                    w.push(annex.to_vec());
                }
                tx.input[1].witness = Witness::from_slice(&w);
                assert_eq!(verify_both(&tx, &prevouts, 1), (false, false), "{label}, annex changed");
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 28);
}

/// A tapscript leaf of `checks` signature checks, `OP_DUP <pk>
/// OP_CHECKSIGVERIFY` repeated and a final `<pk> OP_CHECKSIG`, spent with
/// one signature and an annex of `annex_len` bytes. `pad` bytes of 520-byte
/// pushes in an unexecuted `OP_0 OP_IF ... OP_ENDIF` go first, so a spend can
/// carry the witness weight its signature-check budget needs without a large
/// annex.
fn many_checks_spend(checks: usize, annex_len: usize, pad: usize) -> (Transaction, Vec<TxOut>) {
    let pk = xonly();
    let mut leaf = Vec::new();
    if pad > 0 {
        leaf.extend([0x00, 0x63]); // OP_0 OP_IF
        for _ in 0..pad.div_ceil(523) {
            leaf.extend([0x4d, 0x08, 0x02]); // OP_PUSHDATA2 520
            leaf.extend([0u8; 520]);
        }
        leaf.push(0x68); // OP_ENDIF
    }
    for _ in 0..checks - 1 {
        leaf.push(0x76);
        leaf.extend(push(&pk));
        leaf.push(0xad);
    }
    leaf.extend(push(&pk));
    leaf.push(0xac);
    let (spk, control) = taproot_output(&leaf);
    let (mut tx, prevouts) = spend_of(&[spk]);
    let mut annex = vec![0x50u8];
    annex.resize(annex_len, 0xab);
    let sig = sign(&tx, &prevouts, 0, &leaf, Some(&annex), 0xffff_ffff, TapSighashType::Default);
    let mut w = Witness::new();
    w.push(&sig);
    w.push(&leaf);
    w.push(&control);
    w.push(&annex);
    tx.input[0].witness = w;
    (tx, prevouts)
}

fn time_rust(tx: &Transaction, prevouts: &[TxOut]) -> Duration {
    let mut bytes = Vec::new();
    tx.consensus_encode(&mut bytes).unwrap();
    let spk = prevouts[0].script_pubkey.as_bytes();
    let utxos = [consensus::Utxo { script_pubkey: spk.as_ptr(), script_pubkey_len: spk.len() as u32, value: VALUE as i64 }];
    let t = Instant::now();
    assert!(consensus::verify_with_flags(spk, VALUE, &bytes, Some(&utxos), 0, FLAGS).is_ok());
    t.elapsed()
}

fn time_core(tx: &Transaction, prevouts: &[TxOut]) -> Duration {
    let mut bytes = Vec::new();
    tx.consensus_encode(&mut bytes).unwrap();
    let spk = prevouts[0].script_pubkey.as_bytes();
    let utxos = [kernel_ref::Utxo { script_pubkey: spk.as_ptr(), script_pubkey_len: spk.len() as u32, value: VALUE as i64 }];
    let t = Instant::now();
    assert!(kernel_ref::verify_with_flags(spk, VALUE, &bytes, Some(&utxos), 0, FLAGS).is_ok());
    t.elapsed()
}

/// The annex is hashed once per input, as Core does, not once per signature
/// check. With 8,000 checks over a 128 kB annex the engine hashed about
/// 1 GB, several times Core's cost, and the gap grew with the square of the
/// witness size (43 s against Core's 2.5 s for a 3.3 MB witness in a
/// release build). Signature verification now dominates on both engines.
///
/// The engine is timed against itself, the same 8,000 checks with a
/// 100-byte annex and the witness weight moved into unexecuted script,
/// rather than against Core: the C++ engine is built
/// optimized whatever the test profile (libbitcoinkernel's cmake build),
/// so in a debug test build a comparison with it measures the profile.
/// Core's time is printed for reference; in a release build the two match.
#[test]
fn many_checks_over_a_large_annex_cost_what_they_cost_core() {
    let (tx, prevouts) = many_checks_spend(8_000, 128_000, 0);
    let (small_tx, small_prevouts) = many_checks_spend(8_000, 100, 128_000);
    // Warm both engines' one-time setup (the secp256k1 contexts).
    let (warm_tx, warm_prevouts) = many_checks_spend(2, 100, 0);
    time_rust(&warm_tx, &warm_prevouts);
    time_core(&warm_tx, &warm_prevouts);
    let small = time_rust(&small_tx, &small_prevouts);
    let large = time_rust(&tx, &prevouts);
    let core = time_core(&tx, &prevouts);
    eprintln!("8000 checks: rust {small:?} (100 B annex), {large:?} (128 kB annex); core {core:?} (128 kB)");
    assert!(
        large < small * 3 / 2 + Duration::from_millis(100),
        "a 128 kB annex took {large:?} where a 100-byte one took {small:?}"
    );
}
