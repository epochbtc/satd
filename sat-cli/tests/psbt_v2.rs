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

/// A version 2 PSBT reaches the Signer rather than being refused: the tests
/// further down are what it then does. This one only pins that the parse
/// happens before the key prompt, so a PSBT that was never going to work does
/// not cost the user a key on a terminal first.
#[test]
fn signpsbtwithkey_parses_a_version_2_psbt_before_asking_for_a_key() {
    let psbt = bip375_vector("can finalize: one P2PKH input");
    let mut broken = psbt.clone();
    broken.truncate(psbt.len() / 2);

    let mut child = Command::new(bin())
        .arg("signpsbtwithkey")
        .arg(&broken)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sat-cli runs");
    // Close stdin without writing a key. A binary that asked for one first
    // would report a missing key; this must report the PSBT.
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("completes");

    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("PSBT"),
        "the refusal should be about the PSBT, not the key: {stderr}"
    );
    assert!(!stderr.contains("no private key"), "{stderr}");
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

// ---------------------------------------------------------------------------
// The BIP 375 Signer
// ---------------------------------------------------------------------------

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use satd_psbt::raw::{RawMap, RawPair, RawPsbt};
use satd_psbt::{V2View, keys, sp};

/// A PSBT paying one silent payment recipient from one P2WPKH input, with the
/// previous output already filled in — the shape `utxoupdatepsbt` hands back.
fn sp_psbt(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    wallet: &bitcoin::PrivateKey,
    scan: &bitcoin::secp256k1::PublicKey,
    spend: &bitcoin::secp256k1::PublicKey,
) -> RawPsbt {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let pubkey = wallet.public_key(secp);
    let script = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().expect("compressed"));

    let mut global = RawMap::new();
    global.set(RawPair::new(keys::global::VERSION, Vec::new(), 2u32.to_le_bytes().to_vec()));
    global.set(RawPair::new(keys::global::TX_VERSION, Vec::new(), 2u32.to_le_bytes().to_vec()));
    global.set(RawPair::new(
        keys::global::FALLBACK_LOCKTIME,
        Vec::new(),
        0u32.to_le_bytes().to_vec(),
    ));
    global.set(RawPair::new(keys::global::INPUT_COUNT, Vec::new(), vec![1u8]));
    global.set(RawPair::new(keys::global::OUTPUT_COUNT, Vec::new(), vec![1u8]));
    global.set(RawPair::new(
        keys::global::TX_MODIFIABLE,
        Vec::new(),
        vec![keys::modifiable::INPUTS | keys::modifiable::OUTPUTS],
    ));

    let mut input = RawMap::new();
    input.set(RawPair::new(
        keys::input::PREVIOUS_TXID,
        Vec::new(),
        bitcoin::Txid::from_byte_array([0x31u8; 32])
            .to_byte_array()
            .to_vec(),
    ));
    input.set(RawPair::new(
        keys::input::OUTPUT_INDEX,
        Vec::new(),
        0u32.to_le_bytes().to_vec(),
    ));
    input.set(RawPair::new(
        keys::input::SEQUENCE,
        Vec::new(),
        0xffff_ffffu32.to_le_bytes().to_vec(),
    ));
    input.set(RawPair::new(
        keys::input::WITNESS_UTXO,
        Vec::new(),
        bitcoin::consensus::serialize(&TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: script,
        }),
    ));
    input.set(RawPair::new(
        keys::input::BIP32_DERIVATION,
        pubkey.to_bytes(),
        vec![0u8; 4],
    ));

    let mut output = RawMap::new();
    output.set(RawPair::new(
        keys::output::AMOUNT,
        Vec::new(),
        90_000i64.to_le_bytes().to_vec(),
    ));
    let mut info = scan.serialize().to_vec();
    info.extend_from_slice(&spend.serialize());
    output.set(RawPair::new(keys::output::SP_V0_INFO, Vec::new(), info));

    RawPsbt {
        global,
        inputs: vec![input],
        outputs: vec![output],
    }
}

fn wallet_key() -> bitcoin::PrivateKey {
    bitcoin::PrivateKey::from_slice(&[0x61u8; 32], bitcoin::Network::Regtest).expect("a key")
}

fn run_sign(psbt: &RawPsbt, key: &bitcoin::PrivateKey) -> (i32, String, String) {
    use base64::Engine as _;
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
        .write_all(key.to_wif().as_bytes())
        .expect("writes");
    let out = child.wait_with_output().expect("completes");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn parse(b64: &str) -> RawPsbt {
    use base64::Engine as _;
    RawPsbt::parse(
        &base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("base64"),
    )
    .expect("a PSBT")
}

/// The whole Signer's job, through the shipped binary: an ECDH share, a BIP
/// 374 proof of it, the output script that follows, a frozen transaction, and
/// only then a signature.
#[test]
fn signpsbtwithkey_does_the_bip375_signers_work() {
    let secp = Secp256k1::new();
    let wallet = wallet_key();
    let scan = SecretKey::from_slice(&[0x71u8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x72u8; 32]).unwrap().public_key(&secp);

    let psbt = sp_psbt(&secp, &wallet, &scan, &spend);
    let (code, stdout, stderr) = run_sign(&psbt, &wallet);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stderr.contains("input 0: signed"), "{stderr}");
    assert!(
        stderr.contains("every output script computed and verified"),
        "{stderr}"
    );

    let signed = parse(&stdout);
    let view = V2View::new(&signed).expect("version 2");

    // The share, its proof, and the script it derives to.
    assert!(
        signed
            .global
            .get(keys::global::SP_ECDH_SHARE, &scan.serialize())
            .is_some(),
        "one signer holding the only input writes a global share"
    );
    assert!(
        signed
            .global
            .get(keys::global::SP_DLEQ, &scan.serialize())
            .is_some()
    );
    let report = sp::verify(&view, None).expect("verifies");
    assert_eq!(report.outputs[0].status, sp::OutputStatus::Ready, "{report:?}");
    assert_eq!(report.outputs[0].script_state, sp::ScriptState::Matches);
    assert!(report.extractable());

    // The transaction is frozen, and only then is there a signature.
    assert_eq!(view.tx_modifiable().unwrap(), 0);
    assert!(signed.inputs[0].contains_type(keys::input::PARTIAL_SIG));

    // Two runs must not produce the same proof: BIP 374's auxiliary
    // randomness is fresh per proof, and reusing it across two proofs for one
    // key can leak the secret.
    let (_, again, _) = run_sign(&psbt, &wallet);
    let again = parse(&again);
    assert_ne!(
        signed.global.get(keys::global::SP_DLEQ, &scan.serialize()),
        again.global.get(keys::global::SP_DLEQ, &scan.serialize()),
        "the auxiliary randomness must be fresh for every proof"
    );
    // But the share and the script are a function of the keys, so they must
    // not change.
    assert_eq!(
        signed.global.get(keys::global::SP_ECDH_SHARE, &scan.serialize()),
        again.global.get(keys::global::SP_ECDH_SHARE, &scan.serialize())
    );
    assert_eq!(
        signed.outputs[0].get_single(keys::output::SCRIPT),
        again.outputs[0].get_single(keys::output::SCRIPT)
    );
}

/// A signer that holds none of the eligible inputs writes nothing, signs
/// nothing, and says which inputs still owe a share — exit code 2, the PSBT
/// emitted so the next signer can continue.
#[test]
fn signpsbtwithkey_reports_a_partial_run_rather_than_signing() {
    let secp = Secp256k1::new();
    let wallet = wallet_key();
    let stranger =
        bitcoin::PrivateKey::from_slice(&[0x62u8; 32], bitcoin::Network::Regtest).unwrap();
    let scan = SecretKey::from_slice(&[0x73u8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x74u8; 32]).unwrap().public_key(&secp);

    let psbt = sp_psbt(&secp, &wallet, &scan, &spend);
    let (code, stdout, stderr) = run_sign(&psbt, &stranger);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(stderr.contains("still owe an ECDH share"), "{stderr}");
    assert!(stderr.contains("[0]"), "the message should name the input: {stderr}");

    let out = parse(&stdout);
    // Nothing was signed, and the output still has no script — which is the
    // point: a signature commits to the outputs.
    assert!(!out.inputs[0].contains_type(keys::input::PARTIAL_SIG));
    assert!(out.outputs[0].get_single(keys::output::SCRIPT).is_none());
    // And the transaction is still modifiable, so another party may add an
    // input.
    let view = V2View::new(&out).unwrap();
    assert_ne!(view.tx_modifiable().unwrap(), 0);
}

/// BIP 352 forbids a segwit version 2 or later input anywhere in a transaction
/// paying a silent payment address, so the Signer refuses before it does
/// anything at all.
#[test]
fn signpsbtwithkey_refuses_an_ineligible_transaction() {
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let secp = Secp256k1::new();
    let wallet = wallet_key();
    let scan = SecretKey::from_slice(&[0x75u8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x76u8; 32]).unwrap().public_key(&secp);

    let mut psbt = sp_psbt(&secp, &wallet, &scan, &spend);
    psbt.inputs[0].set(RawPair::new(
        keys::input::WITNESS_UTXO,
        Vec::new(),
        bitcoin::consensus::serialize(&TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_hex(
                "5220000000000000000000000000000000000000000000000000000000000000beef",
            )
            .expect("a segwit v2 script"),
        }),
    ));

    let (code, stdout, stderr) = run_sign(&psbt, &wallet);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("segwit version 2"), "{stderr}");
    assert!(stdout.is_empty(), "nothing should have been emitted");
}

/// The signer must not sign when a share it did not produce does not check
/// out: the script it would commit to is derived from that share.
#[test]
fn signpsbtwithkey_refuses_a_share_that_does_not_verify() {
    let secp = Secp256k1::new();
    let wallet = wallet_key();
    let scan = SecretKey::from_slice(&[0x77u8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x78u8; 32]).unwrap().public_key(&secp);

    let mut psbt = sp_psbt(&secp, &wallet, &scan, &spend);
    // Somebody else's share, with a proof that covers nothing.
    psbt.inputs[0].set(RawPair::new(
        keys::input::SP_ECDH_SHARE,
        scan.serialize().to_vec(),
        spend.serialize().to_vec(),
    ));
    psbt.inputs[0].set(RawPair::new(
        keys::input::SP_DLEQ,
        scan.serialize().to_vec(),
        vec![0x11u8; 64],
    ));

    let (code, stdout, stderr) = run_sign(&psbt, &wallet);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("invalid_proof"), "{stderr}");
    assert!(stdout.is_empty(), "nothing should have been emitted");
}

/// Two signers between them: neither holds every eligible input, so each
/// writes a per-input share, and the second one finishes the job.
#[test]
fn two_signers_cover_a_transaction_neither_could_alone() {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let secp = Secp256k1::new();
    let first = wallet_key();
    let second =
        bitcoin::PrivateKey::from_slice(&[0x63u8; 32], bitcoin::Network::Regtest).unwrap();
    let scan = SecretKey::from_slice(&[0x79u8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x7au8; 32]).unwrap().public_key(&secp);

    let mut psbt = sp_psbt(&secp, &first, &scan, &spend);
    // A second input, belonging to the other signer.
    let pubkey = second.public_key(&secp);
    let script = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().expect("compressed"));
    let mut extra = RawMap::new();
    extra.set(RawPair::new(
        keys::input::PREVIOUS_TXID,
        Vec::new(),
        bitcoin::Txid::from_byte_array([0x32u8; 32])
            .to_byte_array()
            .to_vec(),
    ));
    extra.set(RawPair::new(
        keys::input::OUTPUT_INDEX,
        Vec::new(),
        0u32.to_le_bytes().to_vec(),
    ));
    extra.set(RawPair::new(
        keys::input::SEQUENCE,
        Vec::new(),
        0xffff_ffffu32.to_le_bytes().to_vec(),
    ));
    extra.set(RawPair::new(
        keys::input::WITNESS_UTXO,
        Vec::new(),
        bitcoin::consensus::serialize(&TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: script,
        }),
    ));
    extra.set(RawPair::new(
        keys::input::BIP32_DERIVATION,
        pubkey.to_bytes(),
        vec![0u8; 4],
    ));
    psbt.inputs.push(extra);
    psbt.global.set(RawPair::new(keys::global::INPUT_COUNT, Vec::new(), vec![2u8]));

    // The first signer: a per-input share for its own input, nothing signed.
    let (code, stdout, stderr) = run_sign(&psbt, &first);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(stderr.contains("still owe an ECDH share"), "{stderr}");
    let half = parse(&stdout);
    assert!(
        half.inputs[0]
            .get(keys::input::SP_ECDH_SHARE, &scan.serialize())
            .is_some(),
        "the first signer covered its own input"
    );
    assert!(
        half.inputs[1]
            .get(keys::input::SP_ECDH_SHARE, &scan.serialize())
            .is_none(),
        "and not the one it does not hold"
    );
    assert!(
        half.global
            .get(keys::global::SP_ECDH_SHARE, &scan.serialize())
            .is_none(),
        "a global share would claim to cover an input this signer does not hold"
    );
    assert!(!half.inputs[0].contains_type(keys::input::PARTIAL_SIG));

    // The second signer: the last share, then the scripts, then both
    // signatures — its own and, since the transaction is now determined, the
    // first signer's is still missing, so this run is still partial.
    let (code, stdout, stderr) = run_sign(&half, &second);
    let done = parse(&stdout);
    assert!(
        done.inputs[1]
            .get(keys::input::SP_ECDH_SHARE, &scan.serialize())
            .is_some(),
        "{stderr}"
    );
    let view = V2View::new(&done).expect("version 2");
    let report = sp::verify(&view, None).expect("verifies");
    assert_eq!(report.outputs[0].status, sp::OutputStatus::Ready, "{stderr}");
    assert_eq!(report.outputs[0].script_state, sp::ScriptState::Matches);
    assert_eq!(view.tx_modifiable().unwrap(), 0, "the transaction is frozen");
    // Input 1 is signed; input 0 is not, because this signer does not hold it.
    assert!(done.inputs[1].contains_type(keys::input::PARTIAL_SIG), "{stderr}");
    assert!(!done.inputs[0].contains_type(keys::input::PARTIAL_SIG));
    assert_eq!(code, 2, "one input still unsigned: {stderr}");

    // And the first signer, seeing it again, signs its own input. The scripts
    // are already there, so nothing about the transaction moves.
    let scripts_before = done.outputs[0].get_single(keys::output::SCRIPT).map(<[u8]>::to_vec);
    let (code, stdout, stderr) = run_sign(&done, &first);
    assert_eq!(code, 0, "stderr: {stderr}");
    let finished = parse(&stdout);
    assert_eq!(
        finished.outputs[0].get_single(keys::output::SCRIPT).map(<[u8]>::to_vec),
        scripts_before,
        "the output script must not move once it is computed"
    );
    assert!(finished.inputs[0].contains_type(keys::input::PARTIAL_SIG));
    assert!(finished.inputs[1].contains_type(keys::input::PARTIAL_SIG));
}

// ---------------------------------------------------------------------------
// External signers
// ---------------------------------------------------------------------------

/// Write a shell script that speaks Bitcoin Core's external-signer contract:
/// `enumerate` lists one device, `signtx` prints whatever `reply` says.
fn fake_signer(tag: &str, reply: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let mut path = std::env::temp_dir();
    path.push(format!("satcli-fake-signer-{tag}-{}.sh", std::process::id()));
    let script = format!(
        "#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in\n    enumerate) \
         echo '[{{\"fingerprint\":\"00000000\",\"name\":\"fake\"}}]'; exit 0;;\n    \
         signtx) cat <<'REPLY'\n{reply}\nREPLY\n      exit 0;;\n  esac\ndone\nexit 1\n"
    );
    std::fs::write(&path, script).expect("writes the script");
    let mut perms = std::fs::metadata(&path).expect("stats").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod");
    path
}

fn run_with_signer(psbt_b64: &str, signer: &std::path::Path) -> (i32, String, String) {
    let out = Command::new(bin())
        .arg("signpsbtwithsigner")
        .arg(psbt_b64)
        .arg("--signer")
        .arg(signer)
        .arg("--regtest")
        .output()
        .expect("sat-cli runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// A silent payment PSBT whose shares and scripts are already computed is, by
/// BIP 375's own words, plain PSBTv2. A device that has never heard of BIP 375
/// can sign it — which is the case that works today, and the one worth
/// testing, since no shipping device writes BIP 375 fields.
///
/// The user's assurance in that case is the node's verdict, not the device's
/// screen: the device shows a taproot address, not the `sp1…` one. So what
/// `sat-cli` must do is check the reply.
#[test]
fn an_unaware_signer_may_sign_an_already_computed_silent_payment_psbt() {

    let secp = Secp256k1::new();
    let wallet = wallet_key();
    let scan = SecretKey::from_slice(&[0x7bu8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x7cu8; 32]).unwrap().public_key(&secp);

    // Another signer has already done the BIP 375 work, so this PSBT is
    // complete except for the signature.
    let psbt = sp_psbt(&secp, &wallet, &scan, &spend);
    let (code, computed, stderr) = run_sign(&psbt, &wallet);
    assert_eq!(code, 0, "{stderr}");
    let computed_psbt = parse(&computed);
    assert!(computed_psbt.inputs[0].contains_type(keys::input::PARTIAL_SIG));

    // The device hands the same PSBT back, signature and all.
    let signer = fake_signer("aware", &format!(r#"{{"psbt":"{computed}"}}"#));
    let (code, stdout, stderr) = run_with_signer(&computed, &signer);
    assert_eq!(code, 0, "stderr: {stderr}");
    let out = parse(&stdout);
    assert!(out.inputs[0].contains_type(keys::input::PARTIAL_SIG));
    assert_eq!(
        out.outputs[0].get_single(keys::output::SCRIPT),
        computed_psbt.outputs[0].get_single(keys::output::SCRIPT),
        "the script must come back untouched"
    );
    std::fs::remove_file(&signer).ok();
}

/// A signer that changes a silent payment output's script is refused. The DLEQ
/// proofs exist so a host can check a device's work without trusting it, and
/// this is that check: an emitted PSBT is one `finalizepsbt` away from a
/// transaction, and a silent payment paid to the wrong script is gone.
#[test]
fn a_signer_that_rewrites_a_silent_payment_script_is_refused() {
    use base64::Engine as _;

    let secp = Secp256k1::new();
    let wallet = wallet_key();
    let scan = SecretKey::from_slice(&[0x7du8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x7eu8; 32]).unwrap().public_key(&secp);

    let psbt = sp_psbt(&secp, &wallet, &scan, &spend);
    let (code, computed, stderr) = run_sign(&psbt, &wallet);
    assert_eq!(code, 0, "{stderr}");

    let mut tampered = parse(&computed);
    tampered.outputs[0].set(RawPair::new(
        keys::output::SCRIPT,
        Vec::new(),
        hex::decode("5120000000000000000000000000000000000000000000000000000000000000dead")
            .expect("hex"),
    ));
    let tampered_b64 =
        base64::engine::general_purpose::STANDARD.encode(tampered.serialize());

    let signer = fake_signer("rewrite", &format!(r#"{{"psbt":"{tampered_b64}"}}"#));
    let (code, stdout, stderr) = run_with_signer(&computed, &signer);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("not what its ECDH shares derive to"),
        "{stderr}"
    );
    assert!(stdout.is_empty(), "nothing should have been emitted");
    std::fs::remove_file(&signer).ok();
}

/// And a signer that returns a different transaction entirely.
#[test]
fn a_signer_that_returns_a_different_transaction_is_refused() {
    use base64::Engine as _;

    let secp = Secp256k1::new();
    let wallet = wallet_key();
    let scan = SecretKey::from_slice(&[0x7fu8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x80u8; 32]).unwrap().public_key(&secp);
    let other = SecretKey::from_slice(&[0x81u8; 32]).unwrap().public_key(&secp);

    let psbt = sp_psbt(&secp, &wallet, &scan, &spend);
    let sent = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
    let mut different = sp_psbt(&secp, &wallet, &scan, &other);
    different.outputs[0].set(RawPair::new(
        keys::output::AMOUNT,
        Vec::new(),
        80_000i64.to_le_bytes().to_vec(),
    ));
    let different =
        base64::engine::general_purpose::STANDARD.encode(different.serialize());

    let signer = fake_signer("swap", &format!(r#"{{"psbt":"{different}"}}"#));
    let (code, stdout, stderr) = run_with_signer(&sent, &signer);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("different unsigned transaction"),
        "{stderr}"
    );
    assert!(stdout.is_empty());
    std::fs::remove_file(&signer).ok();
}

/// A signer that simply does not understand the PSBT has its own message
/// relayed, with one line saying what the device would have to support. It is
/// not `sat-cli`'s place to guess which devices have learned BIP 375.
#[test]
fn a_signer_that_refuses_gets_its_message_relayed_with_an_explanation() {
    use base64::Engine as _;

    let secp = Secp256k1::new();
    let wallet = wallet_key();
    let scan = SecretKey::from_slice(&[0x82u8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x83u8; 32]).unwrap().public_key(&secp);
    let psbt = sp_psbt(&secp, &wallet, &scan, &spend);
    let b64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

    let signer = fake_signer(
        "refuse",
        r#"{"error":"Unsupported PSBT version"}"#,
    );
    let (code, stdout, stderr) = run_with_signer(&b64, &signer);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("Unsupported PSBT version"), "{stderr}");
    assert!(
        stderr.contains("support BIP 375"),
        "the added line should say what the device needs: {stderr}"
    );
    assert!(stdout.is_empty());
    std::fs::remove_file(&signer).ok();
}

/// A signer that restates what an input spends is refused, even though every
/// proof in the reply checks out against the restated prevout.
///
/// This is the hole a DLEQ proof does not close on its own. The shares are
/// proved against each input's public key, and the key comes from the previous
/// output the PSBT claims the input spends — evidence the device hands back
/// along with everything else. BIP 370's unique identifier commits to the
/// outpoints but not to that evidence, so a device can swap in a previous
/// output paying a key of its own and then do the whole BIP 375 job honestly
/// against it: the shares verify, the proofs verify, and the script the
/// outputs get is derived from a public key no input has. The recipient's scan
/// never finds the payment and the money is gone.
///
/// The reply below is not tampered with by hand — it is what `sat-cli` itself
/// produces for the substituted input, so every internal check in it passes.
/// The node would catch it at `finalizepsbt`, where the UTXO set says what the
/// inputs really pay; `sat-cli` has the document it sent, which is enough.
#[test]
fn a_signer_that_restates_a_prevout_is_refused() {
    use base64::Engine as _;

    let secp = Secp256k1::new();
    let wallet = wallet_key();
    let attacker = bitcoin::PrivateKey::from_slice(&[0x86u8; 32], bitcoin::Network::Regtest)
        .expect("a key");
    let scan = SecretKey::from_slice(&[0x84u8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x85u8; 32]).unwrap().public_key(&secp);

    // What the host sends: one input paying the wallet's key.
    let sent = base64::engine::general_purpose::STANDARD
        .encode(sp_psbt(&secp, &wallet, &scan, &spend).serialize());

    // What comes back: the same outpoint, the same recipient, the same
    // amount — and a previous output paying the device's own key, with the
    // shares, proofs and script that honestly follow from it.
    let (code, reply, stderr) = run_sign(&sp_psbt(&secp, &attacker, &scan, &spend), &attacker);
    assert_eq!(code, 0, "{stderr}");
    let reply_psbt = parse(&reply);
    assert_ne!(
        reply_psbt.outputs[0].get_single(keys::output::SCRIPT),
        None,
        "the substituted document is complete, which is what makes it dangerous"
    );

    let signer = fake_signer("prevout", &format!(r#"{{"psbt":"{reply}"}}"#));
    let (code, stdout, stderr) = run_with_signer(&sent, &signer);
    assert_eq!(code, 1, "it verifies internally, so only the comparison catches it: {stderr}");
    assert!(
        stderr.contains("changed what input 0 spends")
            || stderr.contains("changed the public key bound to input 0"),
        "{stderr}"
    );
    assert!(stdout.is_empty(), "nothing should have been emitted");
    std::fs::remove_file(&signer).ok();
}

/// Finalizing an input with a scriptSig counts as signing, so it is refused
/// while a silent payment output still has no script — the same as a partial
/// signature or a witness.
///
/// A signature commits to the outputs. One added while an output's script is
/// still to be computed commits to a transaction that is going to change, and
/// a P2SH-P2WPKH input is finalized with `PSBT_IN_FINAL_SCRIPTSIG` rather
/// than a witness alone.
#[test]
fn a_signer_that_finalizes_a_scriptsig_before_the_scripts_is_refused() {
    use base64::Engine as _;

    let secp = Secp256k1::new();
    let wallet = wallet_key();
    let scan = SecretKey::from_slice(&[0x87u8; 32]).unwrap().public_key(&secp);
    let spend = SecretKey::from_slice(&[0x88u8; 32]).unwrap().public_key(&secp);

    // Uncomputed: the output carries its scan and spend keys and no script.
    let psbt = sp_psbt(&secp, &wallet, &scan, &spend);
    let sent = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
    assert!(psbt.outputs[0].get_single(keys::output::SCRIPT).is_none());

    let mut tampered = psbt.clone();
    tampered.inputs[0].set(RawPair::new(
        keys::input::FINAL_SCRIPTSIG,
        Vec::new(),
        vec![0x16, 0x00, 0x14],
    ));
    let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(tampered.serialize());

    let signer = fake_signer("scriptsig", &format!(r#"{{"psbt":"{tampered_b64}"}}"#));
    let (code, stdout, stderr) = run_with_signer(&sent, &signer);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("still has no script"),
        "{stderr}"
    );
    assert!(stdout.is_empty(), "nothing should have been emitted");
    std::fs::remove_file(&signer).ok();
}
