//! `sat-cli`'s handling of a PSBT version 2 / BIP 375 PSBT, driven through the
//! compiled binary.
//!
//! Two behaviours, and the reason each exists. `signpsbtwithkey` refuses a
//! version 2 PSBT *before* it asks for a key: signing one means taking on BIP
//! 375's Signer duties, and prompting first and failing afterwards would put a
//! private key on a terminal for nothing. `signpsbtwithsigner` does not refuse
//! it — for a silent payment the only party that can compute an ECDH share is
//! the one holding the input's private key, so a device is exactly who should
//! be asked.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sat-cli")
}

/// A BIP 375 vector, by the prefix of its description.
fn bip375_vector(prefix: &str) -> String {
    let doc: serde_json::Value =
        serde_json::from_str(satd_psbt::testing::BIP375_VECTORS).expect("vectors parse");
    doc["valid"]
        .as_array()
        .expect("an array")
        .iter()
        .find(|v| {
            v["description"]
                .as_str()
                .unwrap_or_default()
                .starts_with(prefix)
        })
        .unwrap_or_else(|| panic!("no vector starting {prefix:?}"))["psbt"]
        .as_str()
        .expect("base64")
        .to_string()
}

#[test]
fn signpsbtwithkey_refuses_a_version_2_psbt_by_name() {
    let psbt = bip375_vector("can finalize: one P2PKH input");
    let mut child = Command::new(bin())
        .arg("signpsbtwithkey")
        .arg(&psbt)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sat-cli runs");
    // A key on stdin that must never be read. If the refusal came after the
    // key was consumed, this test would still pass — so the real assertion is
    // that stdout carries no PSBT, meaning nothing was signed.
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(
            bitcoin::PrivateKey::from_slice(&[0x11u8; 32], bitcoin::Network::Regtest)
                .expect("a private key")
                .to_wif()
                .as_bytes(),
        )
        .expect("writes");
    let out = child.wait_with_output().expect("completes");

    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.trim(),
        "error: version 2 PSBTs are not supported by this signer yet",
        "the refusal must name the reason: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        "nothing should have been emitted"
    );
}

/// A version 0 PSBT still reaches the signer, so the refusal above is not a
/// blanket one. A refusal test on its own passes against a binary that refuses
/// everything.
#[test]
fn signpsbtwithkey_still_signs_a_version_0_psbt() {
    use base64::Engine as _;
    use bitcoin::hashes::Hash;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        absolute::LockTime, transaction::Version,
    };

    let privkey = bitcoin::PrivateKey::from_slice(&[0x11u8; 32], bitcoin::Network::Regtest)
        .expect("a private key");
    let key = privkey.to_wif();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let pubkey = privkey.public_key(&secp);
    let spk = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().expect("a compressed key"));

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([5u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: spk.clone(),
        }],
    };
    let mut psbt = bitcoin::Psbt::from_unsigned_tx(tx).expect("an unsigned tx");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: spk,
    });
    let b64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

    let mut child = Command::new(bin())
        .arg("signpsbtwithkey")
        .arg(&b64)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sat-cli runs");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(format!("{key}\n").as_bytes())
        .expect("writes");
    let out = child.wait_with_output().expect("completes");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(stderr.contains("input 0: signed"), "{stderr}");
    let signed = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let signed = bitcoin::Psbt::deserialize(
        &base64::engine::general_purpose::STANDARD
            .decode(&signed)
            .expect("base64"),
    )
    .expect("a PSBT");
    assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
}
